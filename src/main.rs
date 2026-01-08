mod io;
mod schema;

use std::{
    collections::BTreeMap,
    fmt::Display,
    hash::{Hash, Hasher},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail};
use cascade::config::file::Spec;
use cascade::policy::{
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

use crate::schema::xml::conf::DatastoreEnum;
#[cfg(not(test))]
use crate::schema::xml::conf::{Host, Mysql};
use crate::schema::xml::kasp::SerialEnum;
use crate::{
    io::{Fs, FsOps},
    schema::xml::conf::Privileges,
};

#[tokio::main]
async fn main() {
    let mut args = std::env::args();
    let prog_name = args.next().unwrap();

    if args.len() != 3 {
        eprintln!(
            "Usage: {prog_name} <path/to/cascade.toml> <path/to/opendnssec/conf.xml> <path/to/write/files/to>"
        );
        eprintln!();
        eprintln!(
            "NOTE: This tool will NOT modify your existing OpenDNSSEC or Cascade installation."
        );
        std::process::exit(1);
    }

    let c_conf_toml_path = args.next().unwrap();
    let o_conf_xml_path = args.next().unwrap();
    let output_dir_path = args.next().unwrap();

    if let Err(err) = Migrator::migrate::<_, RealTerm>(
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
    RepositoryWithoutPinNotYetSupported(String),
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
            MigrateError::RepositoryWithoutPinNotYetSupported(o_repo_name) => {
                write!(f, "HSM repository '{o_repo_name}' lacks a <PIN/>, which is not yet supported by Cascade.")
            }
        }
    }
}

impl std::error::Error for MigrateError {}

struct Migrator;

impl Migrator {
    async fn migrate<IO: FsOps, TERM: Term>(
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

        let mut terminal = TERM::open()?;

        wait_for_enter(&mut terminal, "to continue")?;

        println!();
        println!("Gathering inputs and generating outputs:");
        println!();

        let dbg_dir = format!("{output_dir_path}/debug");
        let k2p_dir = format!("{output_dir_path}/kmip2pkcs11");

        println!("Loading {c_conf_toml_path}...");
        let toml = io.read_to_string(c_conf_toml_path)?;
        let c_conf_spec: Spec = toml::from_str(&toml)?;
        let mut c_conf = cascade::config::Config::default();
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
            return Err(
                MigrateError::RepositoryWithoutPinNotYetSupported(o_repo.name.clone()).into(),
            );
        }

        println!("Loading {}...", o_conf.common.policy_file);
        let xml = io.read_to_string(&o_conf.common.policy_file)?;
        let o_kasps: KASP = process_xml(&xml)?;

        if o_kasps.policies.is_empty() {
            return Err(MigrateError::KaspPolicySetIsEmpty.into());
        }

        let o_zones_path = PathBuf::from_str(&o_conf.enforcer.working_directory)?;
        let o_zones_path = o_zones_path.join("zones.xml");
        println!("Loading {}...", o_zones_path.display());
        let xml = io.read_to_string(&o_zones_path)?;
        let o_zone_list: ZoneList = process_xml(&xml)?;

        // Verify that we can connect to the Enforcer database.
        let mut conn = DbConn::new(&o_conf.enforcer.datastore.datastore).await?;
        let db_version = conn.db_version().await?;
        println!("Found Enforcer database version: {}", db_version.version);

        // (ODS policy name, ODS addns path) -> Cascade policy name
        let mut c_pol_name_by_o_pol_name_plus_addns_path =
            BTreeMap::<(String, Option<String>), String>::new();

        // ODS addns path -> ODS parsed Adapter
        let mut o_adapter_by_addns_path = BTreeMap::<String, Adapter>::new();

        // ODS zone name -> ODS addns path
        let mut o_addns_path_by_o_zone_name = BTreeMap::<String, String>::new();

        // Cascade policy name -> Cascade policy
        let mut c_pol_by_c_pol_name = BTreeMap::<String, cascade::policy::file::Spec>::new();

        // ODS zone name -> ODS signed zone output path
        let _o_signed_zone_output_paths_by_zone_name = BTreeMap::<String, String>::new();

        // Does ODS have at least one zone which it writes to disk rather than
        // serves via XFR?
        let mut o_writes_signed_zones_to_disk = false;

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
                eprintln!("Zone '{}' will be ignored as it has output adapter type DNS but lacks an Outboun configuration and thus will never be written to disk or served via XFR.", o_zone.name);
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

            let hsm_server_id = if o_repo.module.to_lowercase().contains("softhsm") {
                println!(
                    "  NOTE: Future keys for policy '{o_pol_name}' will be generated on-disk instead of using SoftHSM as they are equally secure but much faster when signing."
                );
                None
            } else {
                Some(o_repo.name.clone())
            };

            let o_adapter = addns_path.as_ref().and_then(|addns_path| {
                o_adapter_by_addns_path
                    .get(addns_path)
                    .and_then(|a| a.dns.outbound.as_ref())
            });
            let c_pol = create_cascade_policy(kasp, o_adapter, hsm_server_id.clone())?;
            let out_path = format!("{output_dir_path}/policies/{c_pol_name}.toml");

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

        // Output `cascade` commands for the user to run.
        println!("Generating '{output_dir_path}/commands.sh'...");
        let cmd_file_path = format!("{output_dir_path}/commands.sh");
        let mut cmd_file = io.create(&cmd_file_path)?;

        for c_pol_name in c_pol_by_c_pol_name.keys() {
            writeln!(
                cmd_file,
                "sudo cp {output_dir_path}/policies/{c_pol_name}.toml {c_pol_dir}/"
            )?;
        }
        writeln!(cmd_file, "cascade {c_cli_args} policy reload")?;

        for zone in &o_zone_list.zones {
            let addns_path = o_addns_path_by_o_zone_name.get(&zone.name);
            let Some(c_pol_name) = c_pol_name_by_o_pol_name_plus_addns_path
                .get(&(zone.policy.clone(), addns_path.cloned()))
            else {
                unreachable!()
            };

            let mut source = zone.adapters.input.adapter.path.clone();
            if let Some(o_adapter) = o_adapter_by_addns_path.get(&zone.adapters.input.adapter.path)
            {
                if let Some(inbound) = &o_adapter.dns.inbound {
                    if let Some(rt) = &inbound.request_transfer {
                        // We only support the first source address.
                        if let Some(remote) = rt.remote.first() {
                            let port = remote.port.unwrap_or(53);
                            let ip_addr = IpAddr::from_str(&remote.address)?;
                            source = format!("{ip_addr}:{port}");
                        }
                    }
                }
            }

            writeln!(
                cmd_file,
                "cascade {c_cli_args} zone add --policy {c_pol_name} --source {source} {}",
                zone.name
            )?;

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

        println!();
        println!("Gathering of inputs and generation of outputs is complete.");
        println!();
        println!("Next you will need to perform a sequence of manual steps.");
        println!();
        println!("---------");
        println!(
            "REMINDER: This tool will NOT make changes to your system itself. Only the commands you execute yourself will make changes to your system."
        );
        println!("---------");
        println!();

        let res = ask(
            &mut terminal,
            "Would you first like to preview the complete set of steps before working through them one at a time?",
        )?;
        let mut preview_mode = res == "yes";
        loop {
            if preview_mode {
                println!();
                println!("*** STARTING PREVIEW ***");
            }

            Self::do_steps(
                &mut terminal,
                preview_mode,
                &c_conf,
                c_conf_toml_path,
                &o_conf,
                &cmd_file_path,
                &o_signer_interfaces,
                o_writes_signed_zones_to_disk,
                &k2p_dir,
                &k2p_conf_paths,
            )
            .await?;

            if preview_mode {
                preview_mode = false;
                println!();
                println!("*** PREVIEW FINISHED ***");
            } else {
                break;
            }
        }

        println!(
            "Migration complete. Assuming that you were able to perform each of the steps correctly your Cascade instance should now be signing and serving the zones that were being handled before by OpenDNSSEC."
        );

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_steps<TERM: Term>(
        terminal: &mut TERM,
        review_mode: bool,
        c_conf: &cascade::config::Config,
        c_conf_toml_path: &str,
        o_conf: &Configuration,
        cmd_file_path: &str,
        o_signer_interfaces: &Option<Vec<String>>,
        o_writes_signed_zones_to_disk: bool,
        k2p_dir: &str,
        k2p_conf_paths: &[String],
    ) -> anyhow::Result<()> {
        let mut p = StepPrinter::new(terminal, review_mode);

        p.require_confirmation("WARNING: The commands that will be shown next are examples only and require your review and may need editing.")?;

        if !review_mode {
            println!();
        }

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
                p.println(format!("Configure Cascade to publish on the same interfaces as the OpenDNSSEC Signer by setting [server].servers in {c_conf_toml_path} to:"));
                p.println("  [server]");
                p.println(format!("  servers = [{}]", o_signer_interfaces.join(",")));
                p.next_step()?;
            }
        } else if c_conf.server.servers.is_empty() {
            p.println(format!("Configure Cascade to publish on a UDP+TCP interface by setting [server].servers in {c_conf_toml_path}."));
            p.println("This is needed because unlike OpenDNSSEC, Cascade always makes signed zones available via XFR for secondary nameservers.");
            p.next_step()?;
        }

        if o_writes_signed_zones_to_disk {
            // OpenDNSSEC was not configured to serve XFR. It must therefore have
            // been writing signed zones to files on disk.
            p.println("Deploy a secondary nameserver or use some other tool to retrieve signed zones via XFR and write them to disk.");
            p.println("This is needed because your OpenDNSSEC instance writes signed zones to disk which Cascade is not yet able to do.");
        }

        p.next_step()?;
        p.println("Validate your kmip2pkcs11 configuration files:");
        for k2p_conf_path in k2p_conf_paths.iter() {
            p.cmd(format!(
                "sudo kmip2pkcs11 -c {k2p_conf_path} --check-config"
            ));
        }

        p.next_step()?;
        p.println("Copy the kmi2pkcs11 configuration files to the proper location:");
        if k2p_conf_paths.len() > 1 {
            p.println("NOTE: This should be a location that the kmip2pkcs11 instances will have read access to.");
        } else if let Some(signer) = o_conf.signer.as_ref() {
            if let Some(Privileges {
                user: Some(user), ..
            }) = &signer.privileges
            {
                p.println(format!(
                    "NOTE: Your kmip2pkcs11 instance will run as user '{user}' thus the kmip2pkcs11 configuration file should be readable by this user."
                ));
            }
        }
        p.cmd(format!("sudo cp {k2p_dir}/*.toml /etc/kmip2pkcs11/"));

        p.next_step()?;
        p.println("Stop OpenDNSSEC:");
        p.cmd("sudo ods-control stop");
        p.require_confirmation(
            "WARNING: Executing this command will SHUTDOWN your OpenDNSSEC instance.",
        )?;

        p.next_step()?;
        p.println("Start kmip2pkcs11 once for each HSM to be connected to:");
        if k2p_conf_paths.len() > 1 {
            p.println("--------");
            p.println("NOTE: If using systemd to control kmip2pkcs11 you will need to create separate kmip2pkcs11 units for each kmi2pkcs11 configuration file.");
            p.println("--------");
        }
        if k2p_conf_paths.len() == 1 {
            p.cmd("sudo systemctl start kmip2pkcs11");
            p.println("OR");
        }
        for k2p_conf_path in k2p_conf_paths {
            let file_name = Path::new(&k2p_conf_path).file_name().unwrap();
            p.cmd(format!(
                "sudo kmip2pkcs11 -c /etc/kmip2pkcs11/{}",
                file_name.to_str().unwrap()
            ));
        }

        // TODO: Tell the user to invoke `kmip2pkcs11 --test-hsm` or
        // equivalent here when such functionality becomes available.

        p.next_step()?;
        p.println("Validate your Cascade configuration:");
        p.println(format!(
            "sudo cascaded -c {c_conf_toml_path} --check-config"
        ));

        p.next_step()?;
        p.println("Start Cascade:");
        p.cmd("sudo systemctl start cascaded");
        p.println("OR");
        p.println(format!("E.g. sudo cascaded -c {c_conf_toml_path}"));

        p.next_step()?;
        p.println("Review the generated commands that will be used to configure Cascade:");
        p.println(format!("less {cmd_file_path}"));

        p.next_step()?;
        p.println("Execute the generated commands to configure Cascade:");
        p.cmd(format!("sh -ex {cmd_file_path}"));
        p.require_confirmation(format!("WARNING: This step will cause zones to be added and signed. If you have a lot of zones or very large zones this could use a lot of CPU and/or memory. Please review the commands in '{cmd_file_path}' before executing the script."))?;

        p.last_step()?;

        Ok(())
    }
}

struct StepPrinter<'a, TERM: Term> {
    step_idx: usize,
    step_start: bool,
    terminal: &'a mut TERM,
    review_mode: bool,
}

impl<'a, TERM: Term> StepPrinter<'a, TERM> {
    fn new(terminal: &'a mut TERM, review_mode: bool) -> Self {
        Self {
            step_idx: 1,
            step_start: true,
            terminal,
            review_mode,
        }
    }

    fn cmd<T: Display>(&mut self, cmd: T) {
        self.println(format!("E.g. {cmd}"));
    }

    fn println<T: Display>(&mut self, msg: T) {
        if self.review_mode {
            print!("[DRY RUN] ");
        }
        if self.step_start {
            println!("STEP {}. {}", self.step_idx, msg);
            self.step_start = false;
        } else {
            println!("        {msg}");
        }
    }

    fn require_confirmation<T: Display>(&mut self, msg: T) -> anyhow::Result<()> {
        println!();
        if self.review_mode {
            self.println(msg);
            return Ok(());
        }
        confirm(self.terminal, msg)
    }

    fn next_step(&mut self) -> std::io::Result<()> {
        println!();
        self.step_idx += 1;
        self.step_start = true;
        if !self.review_mode {
            wait_for_enter(self.terminal, "when you have performed this step")?;
            println!();
        }
        Ok(())
    }

    fn last_step(&mut self) -> std::io::Result<()> {
        self.next_step()
    }
}

fn wait_for_enter<TERM: Term, T: Display>(terminal: &mut TERM, msg: T) -> std::io::Result<()> {
    let _ = terminal.prompt(format!("Press ENTER {msg}."))?;
    Ok(())
}

fn ask<TERM: Term, T: Display>(terminal: &mut TERM, msg: T) -> std::io::Result<String> {
    loop {
        let res = terminal.prompt(format!("{msg} [yes/no] "))?;
        match res.as_str() {
            "yes" | "no" => return Ok(res),
            _ => { /* loop */ }
        }
    }
}

fn confirm<TERM: Term, T: Display>(terminal: &mut TERM, msg: T) -> anyhow::Result<()> {
    if ask(
        terminal,
        format!("{msg}\nPlease confirm that you understand."),
    )? == "no"
    {
        bail!("Aborting because 'no' was not entered.");
    }
    Ok(())
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
) -> anyhow::Result<cascade::policy::file::Spec> {
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
    if let Some(key) = zsk {
        if let Some(algorithm) = &algorithm {
            let zsk_algorithm = alg_to_key_parameters(Key::Zsk(key));
            if zsk_algorithm != *algorithm {
                bail!("Unsupported: ZSK algorithm ({zsk_algorithm}) != KSK algorithm ({algorithm})",)
            }
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
    if let Some(output) = output {
        if let Some(notify) = &output.notify {
            for remote in &notify.remote {
                let port = remote.port.unwrap_or(53);
                let ip_addr = IpAddr::from_str(&remote.address)?;
                let addr = SocketAddr::new(ip_addr, port);
                let comms_policy = NameserverCommsPolicy { addr };
                send_notify_to.push(comms_policy);
            }
        }
    }

    let policy = cascade::policy::PolicyVersion {
        name: kasp.name.clone().into_boxed_str(),
        loader: cascade::policy::LoaderPolicy {
            review: ReviewPolicy {
                required: false,
                cmd_hook: None,
            },
        },
        key_manager: cascade::policy::KeyManagerPolicy {
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
            sig_inception_offset: 0,          // TODO
            sig_validity_time: 0,             // TODO
            sig_remain_time: 0,               // TODO
            denial: SignerDenialPolicy::NSec, // TODO
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

    Ok(cascade::policy::file::Spec::build(&policy))
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
    if let Some(idx) = X.iter().position(|c| *c == unit as u8) {
        if (filter)(idx) {
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

fn alg_to_key_parameters(key: Key) -> cascade::policy::KeyParameters {
    let algorithm = match key {
        Key::Ksk(k) => &k.algorithm,
        Key::Zsk(k) => &k.algorithm,
        Key::Csk(k) => &k.algorithm,
    };
    match algorithm.value.as_str() {
        "8" => cascade::policy::KeyParameters::RsaSha256(algorithm.length.parse().unwrap()),
        "10" => cascade::policy::KeyParameters::RsaSha512(algorithm.length.parse().unwrap()),
        "13" => cascade::policy::KeyParameters::EcdsaP256Sha256,
        "14" => cascade::policy::KeyParameters::EcdsaP256Sha256,
        "15" => cascade::policy::KeyParameters::Ed25519,
        "16" => cascade::policy::KeyParameters::Ed448,
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
    Test,
}

impl DbConn {
    #[cfg(not(test))]
    async fn new(datastore: &DatastoreEnum) -> Result<DbConn, sqlx::Error> {
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
        }
    }

    #[cfg(test)]
    async fn new(_datastore: &DatastoreEnum) -> Result<DbConn, sqlx::Error> {
        Ok(Self::Test)
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
            DbConn::Test => Ok(schema::db::DatabaseVersion {
                id: 0,
                rev: 0,
                version: 1,
            }),
        }
    }
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

trait Term {
    type T: Term;
    fn open() -> std::io::Result<Self::T>;
    fn prompt(&mut self, prompt: impl Display) -> std::io::Result<String>;
}

struct RealTerm {
    terminal: terminal_prompt::Terminal,
}

impl Term for RealTerm {
    type T = Self;
    fn open() -> std::io::Result<Self> {
        Ok(Self {
            terminal: terminal_prompt::Terminal::open()?,
        })
    }

    fn prompt(&mut self, prompt: impl Display) -> std::io::Result<String> {
        self.terminal.prompt(prompt)
    }
}

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
        MigrateError, Migrator, Term,
        io::{Fs, FsOps},
    };

    //--- Tests --------------------------------------------------------------

    #[tokio::test]
    async fn output_dir_already_exists() {
        let io = Fs::new();
        io.register_dir("out");

        let res = Migrator::migrate::<_, MockTerm>("conf.toml", "conf.xml", "out", &io).await;
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
            MigrateError::RepositoryWithoutPinNotYetSupported("somehsm".to_string())
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
    async fn kmip2pkcs11_should_use_same_user_as_ods_signer() -> anyhow::Result<()> {
        run_test("1p-1z-signer-privs-user-only").await?;
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
            if !path.is_dir() {
                if let Some(fname) = path.file_name() {
                    let fname = Path::new(fname);
                    let content = std::fs::read_to_string(&path)?;
                    input_paths.insert(fname.to_path_buf());
                    io.register_file(fname, content);
                }
            }
        }

        // Run the migration.
        Migrator::migrate::<_, MockTerm>("conf.toml", "conf.xml", "out", &io).await?;

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
            expected_paths, actual_paths,
            "The expected output paths do not match the generated output paths"
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
                "Content of generated file '{}' does not match the expected content",
                path.display()
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
        let inner_err = err.downcast::<E>();
        assert!(inner_err.is_ok());
        inner_err.unwrap()
    }

    //-------- Helper types --------------------------------------------------

    struct MockTerm;

    impl Term for MockTerm {
        type T = Self;
        fn open() -> std::io::Result<Self> {
            Ok(Self)
        }

        fn prompt(&mut self, _prompt: impl Display) -> std::io::Result<String> {
            Ok("yes".to_string())
        }
    }
}
