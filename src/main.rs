mod io;
mod schema;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    hash::{Hash, Hasher},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail};
use cascaded::config::file::Spec;
use cascaded::policy::{
    AutoConfig, DsAlgorithm, NameserverCommsPolicy, OutboundPolicy, Policy, ReviewPolicy,
    ServerPolicy, SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
};
use domain::base::Ttl;
use kmip2pkcs11_cfg::daemonbase::process::{GroupId, UserId};
use quick_xml::DeError;
use schema::xml::addns::{Adapter, Outbound};
use schema::xml::conf::Configuration;
use schema::xml::kasp::{Csk, KASP, Ksk, Zsk};
use schema::xml::zone_list::ZoneList;
use serde::Deserialize;
#[cfg(not(test))]
use sqlx::{Connection, MySqlConnection, SqliteConnection};

#[cfg(not(test))]
use crate::schema::xml::conf::{Host, Mysql};
use crate::schema::xml::{
    common::{DenialEnum, SerialEnum},
    conf::DatastoreEnum,
    kasp::{KskRollType, ZskRollType},
    signconf::SignerConfiguration,
};
use crate::{
    io::{Fs, FsOps},
    schema::xml::conf::Privileges,
};

#[tokio::main]
async fn main() {
    // Poor mans CLI argument parsing. We don't need Clap (yet).
    if let Some(true) = std::env::args()
        .nth(1)
        .map(|arg| arg == "--version" || arg == "-V")
    {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    let mut args = std::env::args();
    let prog_name = args.next().unwrap();

    if args.len() != 3 || args.any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: {prog_name} [OPTIONS] <path/to/cascade.toml> <path/to/opendnssec/conf.xml> <path/to/write/files/to>"
        );
        println!();
        println!("Options:");
        println!("  -h, --help     Print help");
        println!("  -V, --version  Print version");
        println!();
        println!(
            "NOTE: This tool will NOT modify your existing OpenDNSSEC or Cascade installation."
        );
        std::process::exit(1);
    }

    let mut args = std::env::args();
    let _prog_name = args.next().unwrap();
    let c_conf_toml_path = args.next().unwrap();
    let o_conf_xml_path = args.next().unwrap();
    let output_dir_path = args.next().unwrap();

    if let Err(err) = Migrator::migrate(
        &c_conf_toml_path,
        &o_conf_xml_path,
        &output_dir_path,
        &Fs::new(),
    )
    .await
    {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MigrateError {
    KaspPolicySetIsEmpty,
    OnlyUnusedKaspPoliciesFound,
    NotYetSupportedByCascade(String),
    InconsistentState(String),
    OutdatedState(String),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrateError::KaspPolicySetIsEmpty => {
                f.write_str("No OpenDNSSEC KASP policies defined, nothing to migrate.")
            }
            MigrateError::OnlyUnusedKaspPoliciesFound => {
                f.write_str("None of the found OpenDNSSEC KASP policies appear to be in use, nothing to migrate.")
            },
            MigrateError::NotYetSupportedByCascade(feature) => write!(f, "Cascade does not yet support {feature}."),
            MigrateError::InconsistentState(err) => write!(f, "Inconsistent state: {err}"),
            MigrateError::OutdatedState(err) => write!(f, "Outdated state: {err}"),
        }
    }
}

impl std::error::Error for MigrateError {}

struct Migrator;

impl Migrator {
    async fn migrate<IO: FsOps>(
        c_conf_toml_path: &str,
        o_conf_xml_path: &str,
        output_dir_path: &str,
        io: &IO,
    ) -> anyhow::Result<()> {
        println!("Welcome to ods2cascade.");
        println!();
        println!(
            "This tool will generate files and instructions that you can use to configure Cascade to match the setup of an existing OpenDNSSEC deployment."
        );
        println!();
        println!(
            "NOTE: This tool will NOT modify your existing OpenDNSSEC or Cascade installation."
        );
        println!();
        println!("Provided inputs:");
        println!("  - OpenDNSSEC config file: {o_conf_xml_path}");
        println!("  - Cascade config file   : {c_conf_toml_path}");
        println!("  - Output directory      : {output_dir_path}");
        println!();

        if io.exists(output_dir_path)? {
            bail!(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Output directory '{output_dir_path}' already exists"),
            ));
        }

        println!("Gathering inputs and generating outputs:");
        println!();

        let dbg_dir = format!("{output_dir_path}/debug");
        let k2p_dir = format!("{output_dir_path}/kmip2pkcs11");

        println!("Loading {c_conf_toml_path}...");
        let toml = io.read_to_string(c_conf_toml_path)?;
        let c_conf_spec: Spec = toml::from_str(&toml)?;
        let mut c_conf = cascaded::config::Config::default();
        c_conf_spec.parse_into(&mut c_conf);
        let c_pol_dir = c_conf.policy_dir.clone();
        let c_remote_control_server =
            c_conf.remote_control.servers.first().ok_or_else(|| {
                anyhow!("Cascade config file should define a remote-control server.")
            })?;
        let c_cli_args = format!(
            "--server {}:{}",
            c_remote_control_server.ip(),
            c_remote_control_server.port()
        );

        println!("Loading {o_conf_xml_path}...");
        let xml = io.read_to_string(o_conf_xml_path)?;
        let o_conf: Configuration = process_xml(&xml)?;

        // Check for HSM repositories without a PIN, which Cascade doesn't yet
        // support.
        if let Some(o_repo) = o_conf
            .repository_list
            .repositories
            .iter()
            .find(|r| r.pin.is_none())
        {
            return Err(MigrateError::NotYetSupportedByCascade(format!(
                "HSM repositories without a <PIN/> (see repository '{}')",
                o_repo.name
            ))
            .into());
        }

        println!("Loading {}...", o_conf.common.policy_file);
        let xml = io.read_to_string(&o_conf.common.policy_file)?;
        let o_kasps: KASP = process_xml(&xml)?;

        if o_kasps.policies.is_empty() {
            return Err(MigrateError::KaspPolicySetIsEmpty.into());
        }

        // Check for unsupported policy settings.
        for o_kasp in &o_kasps.policies {
            if o_kasp.passthrough.is_some() {
                return Err(MigrateError::NotYetSupportedByCascade("<Passthrough/>".into()).into());
            }
            if parse_ods_ts(&o_kasp.signatures.resign) > 0 {
                return Err(MigrateError::NotYetSupportedByCascade(
                    "<Resign/> aka incremental signing".into(),
                )
                .into());
            }

            if o_kasp.keys.share_keys.is_some() {
                return Err(MigrateError::NotYetSupportedByCascade("<ShareKeys/>".into()).into());
            }
            if matches!(&o_kasp.keys.purge, Some(d) if parse_ods_ts(d) > 0) {
                return Err(MigrateError::NotYetSupportedByCascade(
                    "<Purge> duration larger than zero".into(),
                )
                .into());
            }
            let mut key_alg = None;
            for ksk in &o_kasp.keys.ksks {
                if key_alg.is_none() {
                    key_alg = Some(ksk.algorithm.clone());
                } else if key_alg.as_ref() != Some(&ksk.algorithm) {
                    return Err(MigrateError::NotYetSupportedByCascade(
                        "Mixed key algorithms".into(),
                    )
                    .into());
                }
                if ksk.standby.is_some() {
                    return Err(MigrateError::NotYetSupportedByCascade("<Standby/>".into()).into());
                }
                if ksk.rfc5011.is_some() {
                    return Err(MigrateError::NotYetSupportedByCascade("<RFC5011/>".into()).into());
                }
                match &ksk.ksk_roll_type {
                    None | Some(KskRollType::KskDoubleSignature) => { /* Supported */ }
                    Some(typ) => {
                        return Err(MigrateError::NotYetSupportedByCascade(format!(
                            "<KskRollType> {typ:?}"
                        ))
                        .into());
                    }
                }
            }
            for zsk in &o_kasp.keys.zsks {
                if key_alg.is_none() {
                    key_alg = Some(zsk.algorithm.clone());
                } else if key_alg.as_ref() != Some(&zsk.algorithm) {
                    return Err(MigrateError::NotYetSupportedByCascade(
                        "Mixed key algorithms".into(),
                    )
                    .into());
                }
                if zsk.standby.is_some() {
                    return Err(MigrateError::NotYetSupportedByCascade("<Standby/>".into()).into());
                }
                match &zsk.zsk_roll_type {
                    None | Some(ZskRollType::ZskPrePublication) => { /* Supported */ }
                    Some(typ) => {
                        return Err(MigrateError::NotYetSupportedByCascade(format!(
                            "<ZskRollType> {typ:?}"
                        ))
                        .into());
                    }
                }
            }
            for csk in &o_kasp.keys.csks {
                if key_alg.is_none() {
                    key_alg = Some(csk.algorithm.clone());
                } else if key_alg.as_ref() != Some(&csk.algorithm) {
                    return Err(MigrateError::NotYetSupportedByCascade(
                        "Mixed key algorithms".into(),
                    )
                    .into());
                }
                if csk.standby.is_some() {
                    return Err(MigrateError::NotYetSupportedByCascade("<Standby/>".into()).into());
                }
                if csk.rfc5011.is_some() {
                    return Err(MigrateError::NotYetSupportedByCascade("<RFC5011/>".into()).into());
                }
                match &csk.csk_roll_type {
                    None => { /* Supported */ }
                    Some(typ) => {
                        return Err(MigrateError::NotYetSupportedByCascade(format!(
                            "<CskRollType> {typ:?}"
                        ))
                        .into());
                    }
                }
            }
        }

        let o_zones_path = PathBuf::from_str(&o_conf.enforcer.working_directory)?;
        let o_zones_path = o_zones_path.join("zones.xml");
        println!("Loading {}...", o_zones_path.display());
        let xml = io.read_to_string(&o_zones_path)?;
        let o_zone_list: ZoneList = process_xml(&xml)?;

        // Verify that we can connect to the Enforcer database.
        let mut db_conn = DbConn::new(&o_conf.enforcer.datastore.datastore, io).await?;
        let db_version = db_conn.db_version().await?;
        println!("Found Enforcer database version: {}", db_version.version);

        // Verify that the set of database zones matches the set of zones.xml zones.
        let zones_file_zone_names = o_zone_list
            .zones
            .iter()
            .map(|z| z.name.clone())
            .collect::<BTreeSet<_>>();
        let db_zones = db_conn.zones().await?;
        let db_zone_names = db_zones
            .iter()
            .map(|z| z.name.clone())
            .collect::<BTreeSet<_>>();
        let diff: Vec<_> = db_zone_names.difference(&zones_file_zone_names).collect();
        if !diff.is_empty() {
            let mut err = "The set of zones defined in the Enforcer zones.xml file differs to that of the Enforcer database:\n".to_string();
            err.push_str("  Database :");
            for zone_name in db_zone_names {
                err.push(' ');
                err.push_str(&zone_name);
            }
            err.push('\n');
            err.push_str("  zones.xml:");
            for zone_name in zones_file_zone_names {
                err.push(' ');
                err.push_str(&zone_name);
            }
            err.push('\n');
            return Err(MigrateError::InconsistentState(err).into());
        }

        // Verify that all of the signconf XML files have been written to disk.
        let db_zones_pending_signconf_write = db_zones
            .iter()
            .filter(|z| z.signconf_needs_writing)
            .map(|z| z.name.clone())
            .collect::<Vec<_>>();
        if !db_zones_pending_signconf_write.is_empty() {
            let mut err = "One or more zones have the signconfNeedsWriting flag set in the Enforcer database:".to_string();
            for zone_name in db_zones_pending_signconf_write {
                err.push(' ');
                err.push_str(&zone_name);
            }
            return Err(MigrateError::OutdatedState(err).into());
        }

        // (ODS policy name, ODS addns path) -> Cascade policy name
        let mut c_pol_name_by_o_pol_name_plus_addns_path =
            BTreeMap::<(String, Option<String>), String>::new();

        // ODS addns path -> ODS parsed Adapter
        let mut o_adapter_by_addns_path = BTreeMap::<String, Adapter>::new();

        // ODS zone name -> ODS addns path
        let mut o_addns_path_by_o_zone_name = BTreeMap::<String, String>::new();

        // Cascade policy name -> Cascade policy
        let mut c_pol_by_c_pol_name = BTreeMap::<String, cascaded::policy::file::Spec>::new();

        // ODS zone name -> ODS signed zone output path
        let _o_signed_zone_output_paths_by_zone_name = BTreeMap::<String, String>::new();

        // ODS zone name -> Details of keys to import into Cascade.
        let mut c_keys_to_import_by_zone_name = BTreeMap::<String, Vec<KeyToImport>>::new();

        // Does ODS have at least one zone which it writes to disk rather than
        // serves via XFR?
        let mut o_writes_signed_zones_to_disk = false;

        // Does ODS use non-zero jitter?
        let mut o_uses_jitter = false;

        // Does ODS use a non-default denial validity period?
        let mut o_uses_non_default_denial_validity = false;

        // Does ODS use a non zero NSEC3 TTL?
        let mut o_uses_non_zero_nsec3_ttl = false;

        // Does ODS uses NSEC3 re-salting?
        let mut o_uses_nsec3_re_salting = false;

        // Does ODS use a non-SHA1 NSEC3 hash algorithm?
        let mut o_uses_non_sha1_nsec3_hash_alg = false;

        // Does ODS use non BCP NSEC3 parameters?
        let mut o_uses_non_bcp_nsec3_params = false;

        // So for each combination of ODS policy and zone output adapter we need
        // a different Cascade policy.
        //
        // Cascade zone -> source (like ODS input adapter)
        // Cascade zone -> policy -> server.outbound (like ODS output adapter)
        // To add a Cascade zone for an ODS zone it needs a policy.
        // That policy will be zone specific regarding its output adapter.
        //
        // o_zone_list.zones each have a policy name and an output adapter.
        // If that output adapter is of type DNS it will refer to an addns.xml
        // file. We load those files and index them by their addns.xml path.
        // If the combination of zone policy name and optional output addns.xml
        // path has not yet been seen, create a policy name for it.
        // If there is no output addns.xml path, use the ODS policy name as the
        // Cascade policy name.
        // If there *is* an output addns.xml path, use the ODS policy name plus
        // a hash of the addns.xml path as the Cascade policy name.
        for o_zone in &o_zone_list.zones {
            // TODO: Process the input adapter.

            // Process the output adapter, loading any addns.xml file referred
            // to and returning its path if one were specified.
            process_adapter(
            &o_zone.adapters.output.adapter,
            &mut o_adapter_by_addns_path,
            io,
        )?.and_then(|o_addns_path| {
            // This zone has an ODS output adapter of type DNS with zone
            // transfer settings defined via an addns.xml file. Confusingly
            // the ODS addns.rnc XML schema file defines that the Outbound
            // element is optional, but if not specified ODS will refuse XFR
            // requests for the zone, but also won't have written the signed
            // zone to a file, presumably making it useless to sign the zone.
            if o_adapter_by_addns_path
                .get(&o_addns_path)
                .map(|adapter| &adapter.dns.outbound)
                .is_none()
            {
                eprintln!("Zone '{}' will be ignored as it has output adapter type DNS but lacks an Outbound configuration and thus will never be written to disk or served via XFR.", o_zone.name);
                return None;
            }

            // Remember the mapping of zone name to output addns path.
            o_addns_path_by_o_zone_name.insert(o_zone.name.clone(), o_addns_path.clone());

            // This zone uses a DNS output adapter. Generate a hashed policy
            // name for Cascade.
            let o_pol_name = o_zone.policy.clone();
            let mut hasher = std::hash::DefaultHasher::new();
            o_addns_path.hash(&mut hasher);
            let hash = hasher.finish().to_string();
            let c_pol_name = sanitize_filename::sanitize(format!("{o_pol_name}-{hash}"));

            // Remember the Cascade policy name for this combination of ODS
            // policy name name and addns path.
            let key = (o_pol_name, Some(o_addns_path));

            c_pol_name_by_o_pol_name_plus_addns_path.insert(key, c_pol_name) //.clone())
        })
        .or_else(|| {
            // This zone was NOT configured in ODS with zone transfer settings
            // and so it must be written by ODS to disk when signed.
            // Remember the Cascade policy name for this ODS policy name.
            o_writes_signed_zones_to_disk = true;
            let o_pol_name = o_zone.policy.clone();
            let o_pol_name = sanitize_filename::sanitize(o_pol_name);
            let key = (o_pol_name.clone(), None);
            c_pol_name_by_o_pol_name_plus_addns_path.insert(key, o_pol_name)
        });
        }

        if c_pol_name_by_o_pol_name_plus_addns_path.is_empty() {
            return Err(MigrateError::OnlyUnusedKaspPoliciesFound.into());
        }

        io.create_dir(output_dir_path)?;
        io.create_dir(&dbg_dir)?;
        io.create_dir(&k2p_dir)?;

        io.dbg_to_file(&c_conf, "cascade_conf", &dbg_dir)?;
        io.dbg_to_file(&o_conf, "ods_conf", &dbg_dir)?;
        io.dbg_to_file(&o_kasps, "ods_kasp", &dbg_dir)?;
        io.dbg_to_file(&o_zone_list, "ods_zone_list", &dbg_dir)?;
        io.dbg_to_file(&o_adapter_by_addns_path, "ods_addns", &dbg_dir)?;
        io.dbg_to_file(
            &o_addns_path_by_o_zone_name,
            "o2c_zone_name_to_addns_path",
            &dbg_dir,
        )?;
        io.dbg_to_file(
            &c_pol_name_by_o_pol_name_plus_addns_path,
            "o2c_ods_policy_name_and_addns_path_to_cascade_policy_name",
            &dbg_dir,
        )?;

        // Generate kmip2pkcs11 configuration fragments.
        let mut k2p_conf_paths = vec![];
        for o_repo in &o_conf.repository_list.repositories {
            let lib_path = PathBuf::from_str(&o_repo.module)
                .map_err(|err| anyhow!("Invalid PKCS#11 module path '{}': {err}", o_repo.module))?;
            let hsm_name = sanitize_filename::sanitize(&o_repo.name);
            let out_path = format!("{k2p_dir}/{hsm_name}.toml");
            println!("Generating '{out_path}'...");

            let mut daemon = kmip2pkcs11_cfg::v1::DaemonConfig::default();
            daemon.log.level = kmip2pkcs11_cfg::v1::LogLevel::Warning;
            daemon.log.target = kmip2pkcs11_cfg::v1::LogTarget::Syslog;
            daemon.daemonize = true;

            // TODO: Add chroot support to kmip2pkcs11 and supply privileges.directory.
            if let Some(Privileges {
                user: Some(user),
                group,
                ..
            }) = o_conf.signer.as_ref().and_then(|c| c.privileges.as_ref())
            {
                let user_id = UserId::from_str(user)
                    .map_err(|err| anyhow!("Invalid user id '{user}': {err}"))?;
                let group = group.as_ref().unwrap_or(user);
                let group_id = GroupId::from_str(group)
                    .map_err(|err| anyhow!("Invalid group id '{group}': {err}"))?;
                daemon.identity = Some((user_id, group_id));
            }

            let pkcs11 = kmip2pkcs11_cfg::v1::Pkcs11Config { lib_path };

            let kmip2pkcs11_conf = kmip2pkcs11_cfg::Config::V1(kmip2pkcs11_cfg::v1::Config {
                daemon,
                pkcs11,
                server: Default::default(),
            });

            let toml = toml::to_string_pretty(&kmip2pkcs11_conf)?;
            let mut out_file = io.create(&out_path)?;
            out_file.write_all(toml.as_bytes())?;
            k2p_conf_paths.push(out_path);
        }

        // Note: zone_list is the old way of managing zones, more recent versions
        // of OpenDNSSEC prefer to manage zones in the database.

        // Generate Cascade policies based on ODS policy and optional addns.xml
        // output adapter.
        for ((o_pol_name, addns_path), c_pol_name) in &c_pol_name_by_o_pol_name_plus_addns_path {
            print!("Creating Cascade policy '{c_pol_name}' from ODS KASP '{o_pol_name}'...");
            if let Some(addns_path) = &addns_path {
                print!(" and ODS ADDNS '{addns_path}'");
            }
            println!(".");

            let kasp = o_kasps
                .policies
                .iter()
                .find(|p| &p.name == o_pol_name)
                .ok_or_else(|| anyhow!("Missing policy '{o_pol_name}'"))?;

            // Determine the HSM to use for generating new keys in future.
            // Possible cases:
            //   - The OpenDNSSEC KASP key definitions all refer to the same
            //     OpenDNSSEC repository. Use this repository as the HSM to
            //     generate keys with, unless:
            //       - The repository module appears to be SoftHSM in which case
            //         don't use a HSM for future key generation at all as ODS
            //         doesn't support on-disk keys but when using SoftHSM (which
            //         uses OpenSSL cryptography) that has much the same security
            //         guarantee as using the much faster on-disk OpenSSL based
            //         cryptography offered by Cascade.
            //   - The OpenDNSSEC KASP key definitions refer to more than one
            //     OpenDNSSEC repository. Abort, we don't know how to handle this
            //     case. Cascade generates new keys using a single HSM defined in
            //     the policy. it can't generate keys using a different HSM per
            //     key type.
            let mut o_kasp_repos = kasp
                .keys
                .ksks
                .iter()
                .map(|r| &r.repository)
                .chain(kasp.keys.zsks.iter().map(|r| &r.repository))
                .chain(kasp.keys.csks.iter().map(|r| &r.repository))
                .collect::<Vec<_>>();
            o_kasp_repos.dedup();
            o_kasp_repos.sort();

            if o_kasp_repos.len() > 1 {
                bail!(
                    "Policy '{o_pol_name}' refers to more than one HSM repository which is not supported by Cascade."
                );
            }

            let o_repo_name = o_kasp_repos
                .first()
                .ok_or_else(|| anyhow!("Expected at least one HSM repository"))?;
            let Some(o_repo) = o_conf
                .repository_list
                .repositories
                .iter()
                .find(|r| &r.name == *o_repo_name)
            else {
                bail!(
                    "Policy '{o_pol_name}' refers to HSM repository '{o_repo_name}' which is not defined in '{o_conf_xml_path}'"
                );
            };

            // TODO: Re-enable this once Cascade supports adding a zone
            // that uses HSM keys (as all zones imported from OpenDNSSEC do)
            // without also requiring that it generate new keys using that
            // HSM. The underlying dnst keyset functionality *does* support
            // this AFAIK, so this is just an issue with the way Cascade
            // interacts with dnst keyset.
            // let hsm_server_id = if o_repo.module.to_lowercase().contains("softhsm") {
            //     println!(
            //         "  NOTE: Future keys for policy '{o_pol_name}' will be generated on-disk instead of using SoftHSM as they are equally secure but much faster when signing."
            //     );
            //     None
            // } else {
            //     Some(o_repo.name.clone())
            // };
            let hsm_server_id = Some(o_repo.name.clone());

            let o_adapter = addns_path.as_ref().and_then(|addns_path| {
                o_adapter_by_addns_path
                    .get(addns_path)
                    .and_then(|a| a.dns.outbound.as_ref())
            });
            let c_pol = create_cascade_policy(kasp, o_adapter, hsm_server_id.clone())?;
            let out_path = format!("{output_dir_path}/policies/{c_pol_name}.toml");

            let ods_jitter = parse_ods_ts(&kasp.signatures.jitter);
            o_uses_jitter |= ods_jitter > 0;

            if kasp.signatures.validity.denial != kasp.signatures.validity.default {
                o_uses_non_default_denial_validity = true;
            }
            if let DenialEnum::nsec3(params) = &kasp.denial.denial {
                if matches!(&params.ttl, Some(d) if parse_ods_ts(d) > 0) {
                    o_uses_non_zero_nsec3_ttl = true;
                }
                if parse_ods_ts(&params.resalt) > 0 {
                    o_uses_nsec3_re_salting = true;
                }
                if params.hash.algorithm != 1 {
                    o_uses_non_sha1_nsec3_hash_alg = true;
                }
                if params.hash.iterations != 0
                    || u8::from_str(&params.hash.salt.length).unwrap() > 0
                    || !params.hash.salt.salt.is_empty()
                {
                    o_uses_non_bcp_nsec3_params = true;
                }
            }

            // As policy saving cannot be told to use the simulated test
            // filesystem, handle the test case separately doing the main
            // things that actually policy saving does.
            #[cfg(not(test))]
            c_pol.save(out_path.as_str().into())?;
            #[cfg(test)]
            {
                let toml = toml::to_string_pretty(&c_pol)?;
                let mut file = io.create(out_path)?;
                file.write_all(toml.as_bytes())?;
            }
            c_pol_by_c_pol_name.insert(c_pol_name.to_string(), c_pol);
        }

        // Collect the details of keys to import per zone.
        for zone in &o_zone_list.zones {
            let db_zone = db_zones
                .iter()
                .find(|z| z.name == zone.name)
                .expect("The zone must exist in the DB as we checked this already");

            let xml = io.read_to_string(&db_zone.signconf_path)?;
            let sign_conf: SignerConfiguration = process_xml(&xml)?;
            let safe_zone_name = sanitize_filename::sanitize(&zone.name);
            io.dbg_to_file(&sign_conf, &format!("sign_conf_{safe_zone_name}"), &dbg_dir)?;

            // Extract the KSK and ZSK keys that have <Publish/> set.
            // TODO: Add support for keys with no locator but with a
            // resource_record field set instead?
            let mut keys_to_import = vec![];
            for key in &sign_conf.zone.keys.keys {
                if key.publish.is_some()
                    && let Some(locator) = &key.locator
                {
                    let flags = u16::from_str(&key.flags.value).unwrap();
                    let algorithm = u8::from_str(&key.algorithm.value).unwrap();
                    let key_type = match (key.ksk, key.zsk) {
                        (None, None) => None,
                        (None, Some(_)) => Some(KeyType::Zsk),
                        (Some(_), None) => Some(KeyType::Ksk),
                        (Some(_), Some(_)) => Some(KeyType::Csk),
                    };

                    if let Some(key_type) = key_type {
                        keys_to_import.push(KeyToImport {
                            locator: locator.clone(),
                            flags,
                            algorithm,
                            key_type,
                        });
                    }
                }
            }

            if !keys_to_import.is_empty() {
                c_keys_to_import_by_zone_name.insert(zone.name.clone(), keys_to_import);
            }
        }

        // Output `cascade` commands for the user to run.
        println!("Generating '{output_dir_path}/commands.sh'...");
        let cmd_file_path = format!("{output_dir_path}/commands.sh");
        let mut cmd_file = io.create(&cmd_file_path)?;

        let c_user = match c_conf.daemon.identity.as_ref().map(|id| id.0.to_string()) {
            Some(username) => username,
            None => {
                // Use the owner of the Cascade config file as the user to grant
                // read access to newly installed Cascade policy files.
                io.owner(c_conf_toml_path)?.ok_or(anyhow!(
                    "Failed to determine ownership of file '{c_conf_toml_path}': Cause unknown",
                ))?
            }
        };

        writeln!(
            cmd_file,
            "# Copy the generated policies to the Cascade policy directory."
        )?;
        for c_pol_name in c_pol_by_c_pol_name.keys() {
            writeln!(
                cmd_file,
                "sudo cp {output_dir_path}/policies/{c_pol_name}.toml {c_pol_dir}/"
            )?;
        }

        writeln!(cmd_file)?;
        writeln!(
            cmd_file,
            "# Set the copied policy file ownership and permissions so that Cascade can read the files."
        )?;
        for c_pol_name in c_pol_by_c_pol_name.keys() {
            writeln!(
                cmd_file,
                "sudo chown {c_user} {c_pol_dir}/{c_pol_name}.toml"
            )?;
            writeln!(cmd_file, "sudo chmod u+r {c_pol_dir}/{c_pol_name}.toml")?;
        }

        writeln!(cmd_file)?;
        writeln!(cmd_file, "# Tell Cascade to reload its policy files.")?;
        writeln!(cmd_file, "cascade {c_cli_args} policy reload")?;

        // Output `hsm add` commands for all HSMs.
        // TODO: Should we restrict this to only those HSMs in use?
        for o_repo in &o_conf.repository_list.repositories {
            let hsm_name = sanitize_filename::sanitize(&o_repo.name);
            // The HSM server is wherever kmip2pkcs11 is running.
            // For OpenDNSSEC it was always effectively localhost, so we
            // output a Cascade command that assumes that kmip2pkcs11 is
            // likewise available on localhost aka 127.0.0.1.
            writeln!(cmd_file)?;
            writeln!(
                cmd_file,
                "# Tell Cascade that a kmip2pkcs11 instance named '{hsm_name}' is available at 127.0.0.1."
            )?;
            writeln!(
                cmd_file,
                "cascade {c_cli_args} hsm add --insecure --username {} --password {} {hsm_name} 127.0.0.1",
                o_repo.token_label,
                o_repo.pin.clone().unwrap()
            )?;
        }

        writeln!(cmd_file)?;
        writeln!(
            cmd_file,
            "# Tell Cascade to load and sign our zones using the appropriate policies."
        )?;
        for zone in &o_zone_list.zones {
            let addns_path = o_addns_path_by_o_zone_name.get(&zone.name);
            let Some(c_pol_name) = c_pol_name_by_o_pol_name_plus_addns_path
                .get(&(zone.policy.clone(), addns_path.cloned()))
            else {
                unreachable!()
            };

            let mut source = zone.adapters.input.adapter.path.clone();
            if let Some(o_adapter) = o_adapter_by_addns_path.get(&zone.adapters.input.adapter.path) &&
               let Some(inbound) = &o_adapter.dns.inbound &&
               let Some(rt) = &inbound.request_transfer &&
               // We only support the first source address.
               let Some(remote) = rt.remote.first()
            {
                let port = remote.port.unwrap_or(53);
                let ip_addr = IpAddr::from_str(&remote.address)?;
                source = format!("{ip_addr}:{port}");
            }

            // Construct the `cascade zone add` command to emit.
            let mut cmd =
                format!("cascade {c_cli_args} zone add --policy {c_pol_name} --source {source} ");

            if let Some(keys) = c_keys_to_import_by_zone_name.get(&zone.name) {
                for key in keys {
                    match key.key_type {
                        KeyType::Zsk => cmd += "--import-zsk-kmip ",
                        KeyType::Ksk => cmd += "--import-ksk-kmip ",
                        KeyType::Csk => cmd += "--import-csk-kmip ",
                    }

                    // The signconf has the CKA_ID locator for the key but
                    // doesn't say which ODS HSM repisitory contains the key,
                    // as ODS will just try all known repositories to find
                    // the key. Cascade can't do that so we need to know which
                    // repository it should be in. We get that from the zone
                    // policy.
                    let cascaded::policy::file::Spec::V1(c_pol) =
                        c_pol_by_c_pol_name.get(c_pol_name).unwrap();
                    let hsm_server_id =
                        c_pol.key_manager.generation.hsm_server_id.as_ref().unwrap();

                    // OpenDNSSEC generates public/private keys which both
                    // have the same CKA_ID. KMIP however requires these
                    // two identifiers to be unique. kmip2pkcs11 handles
                    // this need for uniqueness by suffixing the keys with
                    // _pub and _priv respectively, but usually this mapping
                    // process is invisible to the user of kmip2pkcs11 as
                    // they only see the generated KMIP IDs, not the internal
                    // CKA_IDs. As in this case the keys were not created
                    // by kmip2pkcs11 we have to "uniqify" them ourselves
                    // before passing them to Cascade which in turn will pass
                    // them to kmip2pkcs11. It may be possible in future to
                    // provide CKA_IDs, but not at the time of writing. See
                    // https://github.com/NLnetLabs/kmip2pkcs11/pull/24 for
                    // more information.
                    let public_id = format!("{}_pub", key.locator);
                    let private_id = format!("{}_priv", key.locator);

                    cmd += &format!(
                        "{hsm_server_id} {public_id} {private_id} {} {} ",
                        key.algorithm, key.flags
                    );
                }
            }

            cmd += &zone.name;

            // TODO: Adding the zone can fail if the zone file is readable by
            // the cascaded daemon but not by the cascade CLI, even though the
            // CLI shouldn't need read access to it as it only sends the path
            // to the daemon. It fails when attempting to canonicalize the
            // path to the zone file.
            writeln!(cmd_file, "{cmd}")?;

            cmd_file.flush()?;
        }
        drop(cmd_file);

        // Collect publication interfaces used by OpenDNSSEC.
        let mut o_signer_interfaces = None;

        if let Some(interfaces) = o_conf
            .signer
            .as_ref()
            .map(|signer| &signer.listener.interfaces)
        {
            let non_empty_interfaces = interfaces
                .iter()
                .filter(|i| !i.address.is_empty())
                .map(|i| format!("{}:{}", i.address, i.port))
                .collect::<Vec<String>>();

            if !non_empty_interfaces.is_empty() {
                o_signer_interfaces = Some(non_empty_interfaces);
            }
        }

        let readme_md = Self::generate_readme_markdown(
            &c_conf,
            c_conf_toml_path,
            &o_conf,
            o_conf_xml_path,
            output_dir_path,
            &cmd_file_path,
            &o_signer_interfaces,
            o_writes_signed_zones_to_disk,
            o_uses_jitter,
            o_uses_non_default_denial_validity,
            o_uses_non_zero_nsec3_ttl,
            o_uses_nsec3_re_salting,
            o_uses_non_sha1_nsec3_hash_alg,
            o_uses_non_bcp_nsec3_params,
            &k2p_dir,
            &k2p_conf_paths,
            &db_conn,
        )
        .await?;

        let readme_file_path = format!("{output_dir_path}/README.md");
        let mut readme_file = io.create(&readme_file_path)?;
        readme_file.write_all(readme_md.as_bytes())?;
        readme_file.flush()?;
        drop(readme_file);

        println!();
        println!("Gathering of inputs and generation of outputs is complete.");
        println!(
            "Please consult {readme_file_path} which advises how to proceed in order to perform the migration."
        );

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn generate_readme_markdown(
        c_conf: &cascaded::config::Config,
        c_conf_toml_path: &str,
        o_conf: &Configuration,
        o_conf_xml_path: &str,
        output_dir_path: &str,
        cmd_file_path: &str,
        o_signer_interfaces: &Option<Vec<String>>,
        o_writes_signed_zones_to_disk: bool,
        o_uses_jitter: bool,
        o_uses_non_default_denial_validity: bool,
        o_uses_non_zero_nsec3_ttl: bool,
        o_uses_nsec3_re_salting: bool,
        o_uses_non_sha1_nsec3_hash_alg: bool,
        o_uses_non_bcp_nsec3_params: bool,
        k2p_dir: &str,
        k2p_conf_paths: &[String],
        #[allow(unused_variables)] db_conn: &DbConn,
    ) -> anyhow::Result<String> {
        use std::fmt::Write;

        let mut changes = String::new();

        if o_writes_signed_zones_to_disk {
            writeln!(
                &mut changes,
                "> - Signed zones will NOT be written to disk. Cascade only supports publication of signed zones via XFR. You will need a secondary nameserver or some other tool receive/fetch new signed zone versions via XFR."
            )?;
        }
        if o_uses_non_default_denial_validity {
            writeln!(
                &mut changes,
                "> - Cascade doesn't support <Validity><Denial> != <Validity><Default>"
            )?;
        }
        if o_uses_non_zero_nsec3_ttl {
            writeln!(&mut changes, "> - Cascade <Denial><NSEC3><TTL> != 0")?;
        }
        if o_uses_nsec3_re_salting {
            writeln!(
                &mut changes,
                "> - Cascade doesn't support <Denial><NSEC3><Resalt>"
            )?;
        }
        if o_uses_non_sha1_nsec3_hash_alg {
            writeln!(
                &mut changes,
                "> - Cascade only supports [RFC 5155](https://datatracker.ietf.org/doc/rfc5155/) NSEC3 hashing algorithm 1 (SHA-1). Cascade will use SHA-1 NSEC3 hashing."
            )?;
        }
        if o_uses_non_bcp_nsec3_params {
            writeln!(
                &mut changes,
                "> - Cascade only supports [RFC 9276/BCP 236](https://datatracker.ietf.org/doc/rfc9276/) NSEC3 parameter settings: 0 iterations, no salt. Cascade will use BCP iteration and salt settings."
            )?;
        }
        if o_uses_jitter {
            writeln!(
                &mut changes,
                "> - Cascade implements incremental signing differently than OpenDNSSEC and as such neither needs nor supports the OpenDNSSEC jitter functionality. Jitter settings will be ignored."
            )?;
        }

        if !changes.is_empty() {
            changes = indoc::formatdoc!("## Important differences with Cascade compared to OpenDNSSEC

                > [!WARNING]
                > One or more of your OpenDNSSEC configuration settings is unsupported by or handled differently by Cascade:
                {changes}");
        }

        let mut p = MarkdownWriter::new("#");

        p.writeln(indoc::formatdoc!("
            # How to migrate your OpenDNSSEC instance to Cascade

            This document was generated by `ods2cascade` with the following inputs:
            
              - OpenDNSSEC config file: `{o_conf_xml_path}`
              - Cascade config file   : `{c_conf_toml_path}`
              - Output directory      : `{output_dir_path}`
            
            It suggests a set of steps and commands that can be used to migrate signing and publishing of DNS zones from OpenDNSSEC to Cascade, using data already gathered from OpenDNSSEC, adjusted for how Cascade works, and written to the specified output directory.
            
            No attempt was made to detect specifics of your system outside of OpenDNSSEC itself, or to adjust to them. For example, you will need to adjust the process to allow for things such as:

              - Use of sudo or not.
              - Use of SELinux or AppArmor.
            
            The end result of following the suggested steps, once adjusted for your particular setup, will be that the OpenDNSSEC process no longer runs, communicates with your HSM, signs or serves zones, instead these will all be handled by Cascade.
            
            Note that there may still be tasks remaining after migration that are specific to your setup, including but not limited to:
            
              - Ensuring that OpenDNSSEC is not started again on next boot but instead Cascade is started.
              - Updating your backup and monitoring procedures.
            
            {changes}
            ## Migration steps
        "))?;

        #[cfg(not(test))]
        if matches!(db_conn, DbConn::MySQL(_)) {
            p.writeln(indoc::indoc!(
                "  - Retiring the OpenDNSSEC MySQL database instance."
            ))?;
        }

        p.warning("The commands shown below are examples only and require your review and may need adjusting for your setup.")?;
        p.writeln("")?;

        // Notify the user of any Cascade config changes they need to make.
        // TODO: Use https://github.com/NLnetLabs/ods2cascade/pull/36 when/if ready.
        if let Some(o_signer_interfaces) = o_signer_interfaces {
            let mut different = c_conf.server.servers.len() == o_signer_interfaces.len();

            // Determine if the user has already correctly configured
            // Cascade to match the listener settings of OpenDNSSEC.
            if !different {
                for c_server in &c_conf.server.servers {
                    let c_server = c_server.addr().to_string();
                    if !o_signer_interfaces.contains(&c_server) {
                        different = true;
                        break;
                    }
                }
            }

            if different {
                // TODO: This is brittle as it assumes what the TOML for the
                // Cascade config file should look like, but we can't do better at
                // present, see PR #36 for more info.
                p.println(format!("Configure Cascade to publish on the same interfaces as the OpenDNSSEC Signer by setting [server].servers in {c_conf_toml_path} to:"))?;
                p.println("  [server]")?;
                p.println(format!("  servers = [{}]", o_signer_interfaces.join(",")))?;
                p.next_step()?;
            }
        } else if c_conf.server.servers.is_empty() {
            p.println("Configure Cascade to publish on a UDP+TCP interface.")?;
            p.println("This is needed because unlike OpenDNSSEC, Cascade always makes signed zones available via XFR for secondary nameservers.")?;
            p.println("")?;
            p.println(format!(
                "This can be done using the `servers` setting in `{c_conf_toml_path}`."
            ))?;
            p.println("")?;
            p.code_block(
                "toml",
                indoc::indoc! {r#"
                [server]
                servers = ["0.0.0.0:53"]"#},
            )?;
            p.next_step()?;
        }

        if o_writes_signed_zones_to_disk {
            // OpenDNSSEC was not configured to serve XFR. It must therefore have
            // been writing signed zones to files on disk.
            p.println("Deploy a secondary nameserver.")?;
            p.println(
                "Or use some other tool to retrieve signed zones via XFR and write them to disk.",
            )?;
            p.println("This is needed because your OpenDNSSEC instance writes signed zones to disk which Cascade is not yet able to do.")?;
        }

        p.next_step()?;
        let have_multiple_k2p_configs = k2p_conf_paths.len() > 1;
        let plural = if have_multiple_k2p_configs { "s" } else { "" };
        p.println(format!(
            "Validate your kmip2pkcs11 configuration file{plural}."
        ))?;
        let mut validate_cmds = String::new();
        for k2p_conf_path in k2p_conf_paths.iter() {
            // Sudo is not required here as the config file was written by the
            // current user.
            use std::fmt::Write;
            writeln!(
                &mut validate_cmds,
                "kmip2pkcs11 -c {k2p_conf_path} --check-config"
            )?;
        }
        p.code_block("sh", validate_cmds)?;

        p.next_step()?;
        p.println(format!(
            "Copy the kmip2pkcs11 configuration file{plural} to the proper location."
        ))?;
        p.note(format!("This should be a location that the kmip2pkcs11 instance{plural} will have read access to."))?;
        p.println("")?;
        if !have_multiple_k2p_configs
            && let Some(signer) = o_conf.signer.as_ref()
            && let Some(Privileges {
                user: Some(user), ..
            }) = &signer.privileges
        {
            p.note(format!(
                    "Your kmip2pkcs11 instance will run as user '{user}' thus the kmip2pkcs11 configuration file should be readable by this user."
                ))?;
            p.println("")?;
        }
        // TODO: Should the copied files be chown'd to the kmip2pkcs11 user?
        p.code_block("sh", format!("sudo cp {k2p_dir}/*.toml /etc/kmip2pkcs11/"))?;

        if have_multiple_k2p_configs {
            p.next_step()?;
            p.println("Create additional kmip2pkcs11 systemd units.")?;
            p.println(indoc::indoc!{"
                If using systemd to control kmip2pkcs11 you will need to create separate kmip2pkcs11 units for each of the following kmip2pkcs11 configuration files.
                Each systemd kmip2pkcs11 unit should invoke kmi2pkcs11 with `--config` specifying its own kmi2pkcs11 configuration file.
            "})?;
            for k2p_conf_path in k2p_conf_paths {
                let file_name = Path::new(&k2p_conf_path).file_name().unwrap();
                p.println(format!(
                    "  - `/etc/kmip2pkcs11/{}`",
                    file_name.to_str().unwrap()
                ))?;
            }
        }

        p.next_step()?;
        p.println("Stop OpenDNSSEC.")?;
        p.warning("Executing this command will SHUTDOWN your OpenDNSSEC instance.")?;
        p.println("")?;
        // TODO: Is root the correct user or should we use -u ods or something
        // here?
        p.code_block("sh", "sudo ods-control stop")?;

        p.next_step()?;
        if have_multiple_k2p_configs {
            p.println("Start kmip2pkcs11 once for each HSM to be connected to.")?;
            p.println("If using systemd to control kmip2pkcs11, start each of the kmip2pkcs11 units that you created above.")?;
        } else {
            p.println("Start kmip2pkcs11.")?;
            p.println("If using systemd:")?;
            p.code_block("sh", "sudo systemctl start kmip2pkcs11")?;
        }
        p.println("Otherwise:")?;
        let mut start_cmds = String::new();
        for k2p_conf_path in k2p_conf_paths {
            let file_name = Path::new(&k2p_conf_path).file_name().unwrap();
            use std::fmt::Write;
            writeln!(
                &mut start_cmds,
                "sudo kmip2pkcs11 -c /etc/kmip2pkcs11/{}",
                file_name.to_str().unwrap()
            )?;
        }
        p.code_block("sh", start_cmds)?;

        // TODO: Tell the user to invoke `kmip2pkcs11 --test-hsm` or
        // equivalent here when such functionality becomes available.

        p.next_step()?;
        p.println("Validate your Cascade configuration.")?;
        // TODO: Should this check be run as the cascade user?
        p.code_block(
            "sh",
            format!("sudo cascaded -c {c_conf_toml_path} --check-config"),
        )?;

        p.next_step()?;
        p.println("Start Cascade.")?;
        p.code_block("sh", "sudo systemctl start cascaded")?;
        p.println("OR")?;
        p.code_block("sh", format!("sudo cascaded -c {c_conf_toml_path}"))?;

        p.next_step()?;
        p.println("Review the generated commands that will be used to configure Cascade.")?;
        p.code_block("sh", format!("less {cmd_file_path}"))?;

        p.next_step()?;
        p.println("Execute the generated commands to configure Cascade.")?;
        p.warning(format!("This step will cause zones to be added and signed. If you have a lot of zones or very large zones this could use a lot of CPU and/or memory. Please review the commands in `{cmd_file_path}` before executing the script."))?;
        p.println("")?;
        p.code_block("sh", format!("sh -ex {cmd_file_path}"))?;
        p.last_step()?;

        Ok(p.into())
    }
}

struct MarkdownWriter {
    step_idx: usize,
    step_start: bool,
    buf: String,
    heading: String,
}

impl MarkdownWriter {
    fn new<T: Into<String>>(heading: T) -> Self {
        Self {
            step_idx: 1,
            step_start: true,
            buf: String::new(),
            heading: heading.into(),
        }
    }

    fn writeln<T: Display>(&mut self, msg: T) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        writeln!(&mut self.buf, "{}", msg)
    }

    fn code_block<T: Display>(&mut self, lang: &str, cmd: T) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        indoc::writedoc!(
            &mut self.buf,
            "
            E.g.
            ```{lang}
            {}
            ```
            ",
            cmd.to_string().trim_end()
        )
    }

    fn note<T: Display>(&mut self, msg: T) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        indoc::writedoc!(
            &mut self.buf,
            "
            > [!NOTE]
            > {msg}
            "
        )
    }

    fn warning<T: Display>(&mut self, msg: T) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        indoc::writedoc!(
            &mut self.buf,
            "
            > [!WARNING]
            > {msg}
            "
        )
    }

    fn println<T: Display>(&mut self, msg: T) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        if self.step_start {
            writeln!(&mut self.buf, "{} {}. {}", self.heading, self.step_idx, msg)?;
            writeln!(&mut self.buf)?;
            self.step_start = false;
        } else {
            writeln!(&mut self.buf, "{msg}")?;
        }
        Ok(())
    }

    fn next_step(&mut self) -> std::io::Result<()> {
        self.buf += "\n";
        self.step_idx += 1;
        self.step_start = true;
        Ok(())
    }

    fn last_step(&mut self) -> std::io::Result<()> {
        self.next_step()
    }

    fn into(self) -> String {
        self.buf
    }
}

fn process_adapter<IO: FsOps>(
    adapter: &crate::schema::xml::zone_list::Adapter,
    addns_paths_to_adapters: &mut BTreeMap<String, Adapter>,
    io: &IO,
) -> anyhow::Result<Option<String>> {
    match adapter._type.as_str() {
        "File" => {
            // Zone file, do not load it.
            Ok(None)
        }
        "DNS" => {
            // addns.xml, load it.
            let path = adapter.path.clone();
            if !addns_paths_to_adapters.contains_key(&path) {
                println!("Loading {path}...");
                let xml = io.read_to_string(&path)?;
                let adapter: Adapter = process_xml(&xml)?;
                addns_paths_to_adapters.insert(path.clone(), adapter);
            }
            Ok(Some(path))
        }
        other => Err(anyhow!("Unsupported adapter type '{other}'")),
    }
}

fn process_xml<'de, T: Deserialize<'de>>(xml: &'de str) -> Result<T, DeError> {
    quick_xml::de::from_str(xml)
}

fn create_cascade_policy(
    kasp: &crate::schema::xml::kasp::Policy,
    output: Option<&Outbound>,
    hsm_server_id: Option<String>,
) -> anyhow::Result<cascaded::policy::file::Spec> {
    // NOTE: OpenDNSSEC supports multiple keys per key type (KSK, ZSK, CSK)
    // per policy each having their own algorithm settings. Cascade only
    // supports one key specification per policy. Use the first key found.
    let use_csk = !kasp.keys.csks.is_empty();
    let mut algorithm = None;

    let ksk = kasp.keys.ksks.first();
    if let Some(key) = ksk {
        algorithm = Some(alg_to_key_parameters(Key::Ksk(key)));
    }

    let zsk = kasp.keys.zsks.first();
    if let Some(key) = zsk
        && let Some(algorithm) = &algorithm
    {
        let zsk_algorithm = alg_to_key_parameters(Key::Zsk(key));
        if zsk_algorithm != *algorithm {
            bail!("Unsupported: ZSK algorithm ({zsk_algorithm}) != KSK algorithm ({algorithm})",)
        }
    }

    let csk = kasp.keys.csks.first();
    if let Some(key) = csk {
        if algorithm.is_some() {
            bail!("Unsupported: Cannot use both CSK and KSK/ZSK");
        }
        algorithm = Some(alg_to_key_parameters(Key::Csk(key)));
    }

    let mut send_notify_to = vec![];
    if let Some(output) = output
        && let Some(notify) = &output.notify
    {
        for remote in &notify.remote {
            let port = remote.port.unwrap_or(53);
            let ip_addr = IpAddr::from_str(&remote.address)?;
            let addr = SocketAddr::new(ip_addr, port);
            let comms_policy = NameserverCommsPolicy { addr };
            send_notify_to.push(comms_policy);
        }
    }

    let denial = match &kasp.denial.denial {
        DenialEnum::nsec(_) => SignerDenialPolicy::NSec,
        DenialEnum::nsec3(nsec3) => SignerDenialPolicy::NSec3 {
            opt_out: nsec3.opt_out.is_some(),
        },
    };

    let policy = cascaded::policy::PolicyVersion {
        name: kasp.name.clone().into_boxed_str(),
        loader: cascaded::policy::LoaderPolicy {
            review: ReviewPolicy {
                required: false,
                cmd_hook: None,
            },
        },
        key_manager: cascaded::policy::KeyManagerPolicy {
            hsm_server_id,
            use_csk,
            algorithm: algorithm.unwrap(),
            ksk_validity: ksk.map(|k| parse_ods_ts(&k.lifetime)),
            zsk_validity: zsk.map(|k| parse_ods_ts(&k.lifetime)),
            csk_validity: csk.map(|k| parse_ods_ts(&k.lifetime)),
            auto_ksk: ksk
                .map(|k| manual_or_automatic(k.manual_rollover))
                .unwrap_or_default(),
            auto_zsk: zsk
                .map(|k| manual_or_automatic(k.manual_rollover))
                .unwrap_or_default(),
            auto_csk: csk
                .map(|k| manual_or_automatic(k.manual_rollover))
                .unwrap_or_default(),
            auto_algorithm: AutoConfig::default(), // TODO: What does ODS do for this?
            dnskey_inception_offset: parse_ods_ts(&kasp.signatures.inception_offset),
            dnskey_signature_lifetime: parse_ods_ts(&kasp.signatures.validity.default),
            dnskey_remain_time: parse_ods_ts(&kasp.signatures.refresh),
            cds_inception_offset: parse_ods_ts(&kasp.signatures.inception_offset),
            cds_signature_lifetime: parse_ods_ts(&kasp.signatures.validity.default),
            cds_remain_time: parse_ods_ts(&kasp.signatures.refresh),
            ds_algorithm: DsAlgorithm::Sha256, // TODO: ODS doesn't have this
            default_ttl: Ttl::from_secs(parse_ods_ts(&kasp.keys.ttl)),
            auto_remove: kasp.keys.purge.is_some(), // NOTE: ODS uses a delay, Cascade does not
        },
        signer: SignerPolicy {
            serial_policy: match kasp.zone.soa.serial.serial {
                SerialEnum::counter => SignerSerialPolicy::Counter,
                SerialEnum::datecounter => SignerSerialPolicy::DateCounter,
                SerialEnum::unixtime => SignerSerialPolicy::UnixTime,
                SerialEnum::keep => SignerSerialPolicy::Keep,
            },
            sig_inception_offset: 0, // TODO
            sig_validity_time: 0,    // TODO
            sig_remain_time: 0,      // TODO
            denial,
            review: ReviewPolicy {
                required: false,
                cmd_hook: None,
            },
        },
        server: ServerPolicy {
            outbound: OutboundPolicy {
                accept_xfr_requests_from: vec![], // TODO
                send_notify_to,
            },
        },
    };

    let policy = Policy {
        latest: policy.into(),
        mid_deletion: false,
        zones: Default::default(),
    };

    Ok(cascaded::policy::file::Spec::build(&policy))
}

fn manual_or_automatic(manual_rollover: Option<()>) -> AutoConfig {
    if manual_rollover.is_some() {
        AutoConfig {
            start: false,
            report: false,
            expire: false,
            done: false,
        }
    } else {
        AutoConfig {
            start: true,
            report: true,
            expire: true,
            done: true,
        }
    }
}

// Parse a duration string of the form: P[n]Y[n]M[n]DT[n]H[n]M[n]S
// Based on duration_create_from_string() at:
// https://github.com/opendnssec/opendnssec/blob/b7b69f7090e0180354a342bc54449e065987f3f6/common/duration.c#L111
#[allow(non_snake_case)]
fn parse_ods_ts(timestamp: &str) -> u32 {
    if !timestamp.is_ascii() {
        panic!("Invalid OpenDNSSEC timestamp string '{timestamp}': not ASCII");
    }

    let mut X = timestamp.as_bytes();
    if X[0] != b'P' {
        panic!("Invalid OpenDNSSEC timestamp string '{timestamp}': missing leading 'P'");
    }

    let T_idx = X.iter().position(|c| *c == b'T');
    X = &X[1..]; // Move past P

    let years = parse_ods_ts_fragment(timestamp, 'Y', "years", &mut X, |_| true);
    let months = parse_ods_ts_fragment(timestamp, 'M', "months", &mut X, |idx| {
        T_idx.is_none() || idx < T_idx.unwrap()
    });
    let days = parse_ods_ts_fragment(timestamp, 'D', "days", &mut X, |_| true);

    if let Some(T_idx) = T_idx {
        X = &timestamp.as_bytes()[T_idx + 1..];
    }

    let hours = parse_ods_ts_fragment(timestamp, 'H', "hours", &mut X, |_| true);
    let minutes = parse_ods_ts_fragment(timestamp, 'M', "minutes", &mut X, |idx| {
        T_idx.is_some() && idx > T_idx.unwrap()
    });
    let seconds = parse_ods_ts_fragment(timestamp, 'S', "seconds", &mut X, |_| true);

    let weeks = parse_ods_ts_fragment(timestamp, 'S', "seconds", &mut X, |_| {
        years.is_none()
            && months.is_none()
            && days.is_none()
            && T_idx.is_none()
            && hours.is_none()
            && minutes.is_none()
            && seconds.is_none()
    });

    let mut ts: u32 = 0;
    if let Some(v) = years {
        ts += v * 365 * 24 * 60 * 60;
    }
    if let Some(v) = months {
        ts += v * 31 * 24 * 60 * 60;
    }
    if let Some(v) = weeks {
        ts += v * 7 * 24 * 60 * 60;
    }
    if let Some(v) = days {
        ts += v * 24 * 60 * 60;
    }
    if let Some(v) = hours {
        ts += v * 60 * 60;
    }
    if let Some(v) = minutes {
        ts += v * 60;
    }
    if let Some(v) = seconds {
        ts += v;
    }
    ts
}

fn parse_ods_ts_fragment<T: Fn(usize) -> bool>(
    timestamp: &str,
    unit: char,
    unit_name: &str,
    #[allow(non_snake_case)] X: &mut &[u8],
    filter: T,
) -> Option<u32> {
    if let Some(idx) = X.iter().position(|c| *c == unit as u8)
        && (filter)(idx)
    {
        let str = &X[..idx];
        let (rest, Some(v)) = atoi_with_rest(str) else {
            panic!(
                "Invalid OpenDNSSEC timestamp string '{timestamp}': invalid {unit_name} {}",
                String::from_utf8(str.to_vec()).unwrap()
            );
        };
        *X = rest;
        return Some(v);
    }
    None
}

// From: https://pages.pvv.ntnu.no/Projects/mysqladm-rs/main/docs/atoi/index.html
fn atoi_with_rest<I: atoi::FromRadix10>(text: &[u8]) -> (&[u8], Option<I>) {
    match I::from_radix_10(text) {
        (_, 0) => (text, None),
        (n, used) => (&text[used..], Some(n)),
    }
}

fn alg_to_key_parameters(key: Key) -> cascaded::policy::KeyParameters {
    let algorithm = match key {
        Key::Ksk(k) => &k.algorithm,
        Key::Zsk(k) => &k.algorithm,
        Key::Csk(k) => &k.algorithm,
    };
    match algorithm.value.as_str() {
        "8" => cascaded::policy::KeyParameters::RsaSha256(algorithm.length.parse().unwrap()),
        "10" => cascaded::policy::KeyParameters::RsaSha512(algorithm.length.parse().unwrap()),
        "13" => cascaded::policy::KeyParameters::EcdsaP256Sha256,
        "14" => cascaded::policy::KeyParameters::EcdsaP256Sha256,
        "15" => cascaded::policy::KeyParameters::Ed25519,
        "16" => cascaded::policy::KeyParameters::Ed448,
        alg => panic!("Unsupported algorithm number {alg}"),
    }
}

enum Key<'a> {
    Ksk(&'a Ksk),
    Zsk(&'a Zsk),
    Csk(&'a Csk),
}

/// A wrapper around the sqlx MySQL and SQLite database drivers.
///
/// This wrapper exists because the sqlx `connect()` fn returns different
/// concrete types for different database drivers so making a database query
/// requires type specific code.
///
/// The sqlx crate also offers `AnyConnection` to abstract over the database
/// in use but that doesn't support u64 and u32 field types which we use in
/// many places to model the OpenDNSSEC database fields so we can't use that
/// either.
///
/// Perhaps a Box<dyn Connection> approach might be possible, but it was
/// quicker and simnpler to use an enum based wrapper approach plus we don't
/// need to support arbitrary database drivers so dyn is overkill, an enum
/// over the concrete drivers that we know we need to support is enough.
enum DbConn {
    #[cfg(not(test))]
    MySQL(sqlx::MySqlConnection),
    #[cfg(not(test))]
    SQLite(sqlx::SqliteConnection),
    #[cfg(test)]
    Test(TestDbSnapshot),
}

#[cfg(test)]
#[allow(non_snake_case)]
#[derive(Deserialize)]
struct TestDbSnapshot {
    pub databaseVersion: schema::db::DatabaseVersion,
    pub zone: Vec<schema::db::zone::Zone>,
}

impl DbConn {
    #[cfg(not(test))]
    async fn new<IO: FsOps>(datastore: &DatastoreEnum, _io: &IO) -> Result<DbConn, sqlx::Error> {
        match datastore {
            DatastoreEnum::mysql(Mysql {
                host,
                database,
                username,
                password,
            }) => {
                let (host, port) = match host {
                    Some(Host { address, port }) => (address.as_str(), *port),
                    None => ("127.0.0.1", 3306),
                };
                let url = format!("mysql://{username}:{password}@{host}:{port}/{database}");
                println!("Connecting to MySQL Enforcer database at {url}...");
                MySqlConnection::connect(&url).await.map(DbConn::MySQL)
            }
            DatastoreEnum::sqlite(db) => {
                let url = format!("sqlite://{}", db.0);
                println!("Connecting to SQLite Enforcer database at {url}...");
                SqliteConnection::connect(&url).await.map(DbConn::SQLite)
            }
            DatastoreEnum::test(_) => panic!("The test datastore is only for use by tests"),
        }
    }

    #[cfg(test)]
    async fn new<IO: FsOps>(datastore: &DatastoreEnum, io: &IO) -> Result<DbConn, sqlx::Error> {
        match datastore {
            DatastoreEnum::mysql(_) => panic!(
                "Tests don't currently support the <MySQL> datastore type, use <Test>db.ron</Test> instead"
            ),
            DatastoreEnum::sqlite(_) => panic!(
                "Tests don't currently support the <SQLite> datastore type, use <Test>db.ron</Test> instead"
            ),
            DatastoreEnum::test(ron_data_path) => {
                let ron_data = io.read_to_string(ron_data_path)?;
                let snapshot: TestDbSnapshot = ron::from_str(&ron_data).map_err(|err| {
                    sqlx::Error::Io(std::io::Error::other(format!(
                        "Failed to parse test db snapshot: {err}"
                    )))
                })?;
                Ok(Self::Test(snapshot))
            }
        }
    }

    async fn db_version(&mut self) -> Result<schema::db::DatabaseVersion, sqlx::Error> {
        // TODO: If we end up writing a lot of queries it might be good to
        // extract the common code into a helper function or even a proc
        // macro.
        #[cfg(not(test))]
        const Q: &str = "SELECT * FROM databaseversion";
        match self {
            #[cfg(not(test))]
            DbConn::MySQL(c) => sqlx::query_as(Q).fetch_one(c).await,
            #[cfg(not(test))]
            DbConn::SQLite(c) => sqlx::query_as(Q).fetch_one(c).await,
            #[cfg(test)]
            DbConn::Test(db) => Ok(db.databaseVersion.clone()),
        }
    }

    async fn zones(&mut self) -> Result<Vec<schema::db::zone::Zone>, sqlx::Error> {
        #[cfg(not(test))]
        const Q: &str = "SELECT * FROM zone";
        match self {
            #[cfg(not(test))]
            DbConn::MySQL(c) => sqlx::query_as(Q).fetch_all(c).await,
            #[cfg(not(test))]
            DbConn::SQLite(c) => sqlx::query_as(Q).fetch_all(c).await,
            #[cfg(test)]
            DbConn::Test(db) => Ok(db.zone.clone()),
        }
    }
}

struct KeyToImport {
    pub locator: String,
    pub flags: u16,
    pub algorithm: u8,
    pub key_type: KeyType,
}

enum KeyType {
    Zsk,
    Ksk,
    Csk,
}

// TESTING
// let zones = sqlx::query_as::<_, schema::db::zone::Zone>("SELECT * FROM zone")
//     .fetch_all(&mut conn)
//     .await?;
// dbg!(zones);

// let policies = sqlx::query_as::<_, schema::db::policy::Policy>("SELECT * FROM policy")
//     .fetch_all(&mut conn)
//     .await?;
// dbg!(policies);

// let policy_keys = sqlx::query_as::<_, schema::db::policy::Key>("SELECT * FROM policyKey")
//     .fetch_all(&mut conn)
//     .await?;
// dbg!(policy_keys);

#[cfg(test)]
mod test {
    use std::{
        collections::HashSet,
        fmt::{Debug, Display},
        path::{Path, PathBuf},
        str::FromStr,
    };

    use pretty_assertions::assert_eq;

    use crate::{
        MigrateError, Migrator,
        io::{Fs, FsOps},
    };

    //--- Tests --------------------------------------------------------------

    #[tokio::test]
    async fn output_dir_already_exists() {
        let io = Fs::new();
        io.register_dir("out");

        let res = Migrator::migrate("conf.toml", "conf.xml", "out", &io).await;
        let v = to_inner_err::<_, std::io::Error>(res);
        assert_eq!(v.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[tokio::test]
    async fn at_least_one_policy_required() -> anyhow::Result<()> {
        let res = run_test("minimal").await;
        let v = to_inner_err::<_, MigrateError>(res);
        assert_eq!(v, MigrateError::KaspPolicySetIsEmpty);
        Ok(())
    }

    #[tokio::test]
    async fn passthrough_not_supported_by_cascade_yet() -> anyhow::Result<()> {
        let res = run_test("1p-1z-with-passthrough").await;
        let v = to_inner_err::<_, MigrateError>(res);
        assert_eq!(
            v,
            MigrateError::NotYetSupportedByCascade("<Passthrough/>".into())
        );
        Ok(())
    }

    #[tokio::test]
    async fn single_policy_no_zone() -> anyhow::Result<()> {
        let res = run_test("1p-0z").await;
        let v = to_inner_err::<_, MigrateError>(res);
        assert_eq!(v, MigrateError::OnlyUnusedKaspPoliciesFound);
        Ok(())
    }

    #[tokio::test]
    async fn single_policy_no_zone_missing_hsm_pin() -> anyhow::Result<()> {
        let res = run_test("1p-0z-missing-hsm-pin").await;
        let v = to_inner_err::<_, MigrateError>(res);
        assert_eq!(
            v,
            MigrateError::NotYetSupportedByCascade(
                "HSM repositories without a <PIN/> (see repository 'somehsm')".into()
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn single_policy_one_zone() -> anyhow::Result<()> {
        run_test("1p-1z").await?;
        Ok(())
    }

    #[tokio::test]
    async fn kmip2pkcs11_should_use_same_user_and_group_as_ods_signer() -> anyhow::Result<()> {
        run_test("1p-1z-signer-privs-user-and-group").await?;
        Ok(())
    }

    #[tokio::test]
    async fn single_policy_two_zones_two_hsms() -> anyhow::Result<()> {
        run_test("1p-2z-2hsm").await?;
        Ok(())
    }

    #[tokio::test]
    async fn kmip2pkcs11_should_use_same_user_as_ods_signer() -> anyhow::Result<()> {
        run_test("1p-1z-signer-privs-user-only").await?;
        Ok(())
    }

    #[tokio::test]
    async fn require_consistent_zones_xml() -> anyhow::Result<()> {
        let res = run_test("1p-1z-inconsistent-zones-xml").await;
        let v = to_inner_err::<_, MigrateError>(res);
        assert!(matches!(v, MigrateError::InconsistentState(_)));
        Ok(())
    }

    #[tokio::test]
    async fn require_signconf_written_true() -> anyhow::Result<()> {
        let res = run_test("1p-1z-signconf-write-pending").await;
        let v = to_inner_err::<_, MigrateError>(res);
        assert!(matches!(v, MigrateError::OutdatedState(_)));
        Ok(())
    }

    #[tokio::test]
    async fn force_nsec3_to_bcp_settings() -> anyhow::Result<()> {
        run_test("1p-1z-non-bcp-nsec3").await?;
        Ok(())
    }

    #[tokio::test]
    async fn warn_about_jitter() -> anyhow::Result<()> {
        run_test("1p-1z-with-jitter").await?;
        Ok(())
    }

    //--- Helper functions ---------------------------------------------------

    async fn run_test(test_name: &'static str) -> anyhow::Result<Fs> {
        let test_dir = PathBuf::from_str(&format!("./test-data/{test_name}/")).unwrap();

        // Create a simulated file system to read input files from and write
        // generated outputs to.
        let io = Fs::new();

        // Remember the input paths used.
        let mut input_paths = HashSet::new();

        // Add test inputs to the simulated filesystem.
        for entry in std::fs::read_dir(&test_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir()
                && let Some(fname) = path.file_name()
            {
                let fname = Path::new(fname);
                let content = std::fs::read_to_string(&path)?;
                input_paths.insert(fname.to_path_buf());
                io.register_file(fname, content);
            }
        }

        // Run the migration.
        Migrator::migrate("conf.toml", "conf.xml", "out", &io).await?;

        // Verify the expected outputs
        let mut expected_paths = HashSet::new();
        let expected_dir = test_dir.join("expected");
        get_paths_in_dir(&expected_dir, &mut expected_paths)?;

        // Normalize the paths.
        let mut expected_paths = expected_paths
            .iter()
            .map(|p| {
                p.strip_prefix(&expected_dir).unwrap_or_else(|_| {
                    panic!("No {} in '{}?", expected_dir.display(), p.display())
                })
            })
            .collect::<Vec<_>>();
        expected_paths.sort();

        let actual_paths = io.file_paths();
        let mut actual_paths = actual_paths
            .iter()
            // Filter out the input paths, we're only interested in generated
            // outputs
            .filter(|p| !input_paths.contains(*p))
            // Filter out generated debug files.
            .filter(|p| !p.starts_with("debug/"))
            .map(|p| {
                p.strip_prefix("out/")
                    .unwrap_or_else(|_| panic!("No 'out/' in '{}'?", p.display()))
            })
            .collect::<Vec<_>>();
        actual_paths.sort();

        // Compare the set of expected vs actual output paths.
        assert_eq!(
            expected_paths,
            actual_paths,
            "The files in '{}' do not match the generated output files",
            expected_dir.display()
        );

        // Compare the contents of the expected vs actual output files.
        for path in actual_paths {
            // Load the expected file content.
            let expected = std::fs::read_to_string(expected_dir.join(path))?;
            // Load the actual generated file content.
            let actual = io.read_to_string(format!("out/{}", path.display()))?;
            // Compare the two.
            assert_eq!(
                expected,
                actual,
                "Expected test output '{}' does not match the actual output '{}'",
                expected_dir.join(path).display(),
                path.display(),
            );
        }

        Ok(io)
    }

    fn get_paths_in_dir<P: AsRef<Path>>(
        path: P,
        out_paths: &mut HashSet<PathBuf>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                get_paths_in_dir(path, out_paths)?;
            } else {
                out_paths.insert(path.to_path_buf());
            }
        }
        Ok(())
    }

    fn to_inner_err<T, E>(res: Result<T, anyhow::Error>) -> E
    where
        E: Display + Debug + Send + Sync + 'static,
    {
        assert!(res.is_err());
        let err = res.err().unwrap();
        match err.downcast::<E>() {
            Err(err) => {
                panic!(
                    "Expected inner error of type {} but got {err:#?}",
                    std::any::type_name::<E>()
                );
            }
            Ok(v) => v,
        }
    }
}
