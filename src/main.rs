mod schema;

use std::{
    collections::BTreeMap,
    fs::{File, create_dir},
    hash::{Hash, Hasher},
    io::{ErrorKind, Write},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use cascade::config::file::Spec;
use cascade::policy::{
    AutoConfig, DsAlgorithm, NameserverCommsPolicy, OutboundPolicy, Policy, ReviewPolicy,
    ServerPolicy, SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
};
use domain::base::Ttl;
use quick_xml::DeError;
use schema::xml::addns::{Adapter, Outbound};
use schema::xml::conf::Configuration;
use schema::xml::kasp::{Csk, KASP, Ksk, Zsk};
use schema::xml::zone_list::ZoneList;
use serde::Deserialize;
use sqlx::{Connection, MySqlConnection, SqliteConnection};

use crate::schema::xml::{
    conf::{DatastoreEnum, Host, Mysql},
    kasp::SerialEnum,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let prog_name = args.next().unwrap();

    if args.len() != 3 {
        eprintln!(
            "Usage: {prog_name} <path/to/cascade.toml> <path/to/opendnssec/conf.xml> <path/to/write/files/to>"
        );
        std::process::exit(1);
    }

    let c_conf_toml_path = args.next().unwrap();
    let o_conf_xml_path = args.next().unwrap();
    let output_dir_path = args.next().unwrap();

    let dbg_dir = format!("{output_dir_path}/debug");
    let k2p_dir = format!("{output_dir_path}/kmi2pkcs11");
    let c_cli_args = "--server <C_CLI_SERVER_ARG_TODO>";

    mk_nice_io_err(
        create_dir(&output_dir_path),
        format!("create directory '{output_dir_path}'"),
    );
    mk_nice_io_err(
        create_dir(&dbg_dir),
        format!("create directory '{dbg_dir}'"),
    );
    mk_nice_io_err(
        create_dir(&k2p_dir),
        format!("create directory '{k2p_dir}'"),
    );

    println!("Loading {c_conf_toml_path}...");
    let toml = std::fs::read_to_string(&c_conf_toml_path).unwrap();
    let c_conf_spec: Spec = toml::from_str(&toml).unwrap();
    let mut c_conf = cascade::config::Config::default();
    c_conf_spec.parse_into(&mut c_conf);
    let c_pol_dir = c_conf.policy_dir.clone();
    dbg_to_file(&c_conf, "cascade_conf", &dbg_dir);

    println!("Loading {o_conf_xml_path}...");
    let xml = std::fs::read_to_string(o_conf_xml_path).unwrap();
    let o_conf: Configuration = process_xml(&xml).unwrap();
    dbg_to_file(&o_conf, "ods_conf", &dbg_dir);

    println!("Loading {}...", o_conf.common.policy_file);
    let xml = std::fs::read_to_string(&o_conf.common.policy_file).unwrap();
    let o_kasps: KASP = process_xml(&xml).unwrap();
    dbg_to_file(&o_kasps, "ods_kasp", &dbg_dir);

    let o_zones_path = PathBuf::from_str(&o_conf.enforcer.working_directory).unwrap();
    let o_zones_path = o_zones_path.join("zones.xml");
    println!("Loading {}...", o_zones_path.display());
    let xml = std::fs::read_to_string(&o_zones_path).unwrap();
    let o_zone_list: ZoneList = process_xml(&xml).unwrap();
    dbg_to_file(&o_zone_list, "ods_zone_list", &dbg_dir);

    // Verify that we can connect to the Enforcer database.
    let mut conn = DbConn::new(&o_conf.enforcer.datastore.datastore).await?;
    let db_version = conn.db_version().await?;
    println!("Enforcer database version: {}", db_version.version);

    // Generate kmip2pkcs11 configuration fragments.
    for o_repo in o_conf.repository_list.repositories {
        let lib_path = o_repo.module;
        let repo_name = sanitize_filename::sanitize(o_repo.name);
        let out_path = format!("{k2p_dir}/{repo_name}.toml");
        println!("Generating '{out_path}'...");
        let mut out_file =
            File::create(out_path).expect("Should be able to write the kmip2pkcs11 file");
        writeln!(out_file, r#"lib_path = "{lib_path}""#).unwrap();
    }

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
        )
        .unwrap()
        .and_then(|o_addns_path| {
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
            // and so it must be a
            // Remember the Cascade policy name for this ODS policy name.
            let o_pol_name = o_zone.policy.clone();
            let o_pol_name = sanitize_filename::sanitize(o_pol_name);
            let key = (o_pol_name.clone(), None);
            c_pol_name_by_o_pol_name_plus_addns_path.insert(key, o_pol_name)
        });
    }

    dbg_to_file(&o_adapter_by_addns_path, "ods_addns", &dbg_dir);
    dbg_to_file(
        &o_addns_path_by_o_zone_name,
        "o2c_zone_name_to_addns_path",
        &dbg_dir,
    );
    dbg_to_file(
        &c_pol_name_by_o_pol_name_plus_addns_path,
        "o2c_ods_policy_name_and_addns_path_to_cascade_policy_name",
        &dbg_dir,
    );

    // Note: zone_list is the old way of managing zones, more recent versions
    // of OpenDNSSEC prefer to manage zones in the database.

    // TODO: Create an add hsm command based on config.
    // TODO: Create policies based on conf.common.policy.
    // TODO: Create a policy for each policy referred to by zones in zone_list.
    // TODO: Create a zone for each zone in zone_list with the right policy.
    // NOTE: All policies should reference the hsm created based on config above.
    // for each Cascade policy to generate, generate it based on a given ODS
    // KASP and addns.
    let hsm_server_id = "TODO".to_string();

    // Generate Cascade policies based on ODS policy and optional addns.xml
    // output adapter.
    for ((o_pol_name, addns_path), c_pol_name) in &c_pol_name_by_o_pol_name_plus_addns_path {
        print!("Creating Cascade policy '{c_pol_name}' from ODS KASP '{o_pol_name}'");
        if let Some(addns_path) = &addns_path {
            print!(" and ODS ADDNS '{addns_path}'");
        }
        println!(".");

        let kasp = o_kasps
            .policies
            .iter()
            .find(|p| &p.name == o_pol_name)
            .unwrap();
        let o_adapter = addns_path.as_ref().and_then(|addns_path| {
            o_adapter_by_addns_path
                .get(addns_path)
                .map(|a| a.dns.outbound.as_ref())
                .flatten()
        });
        let c_pol = create_cascade_policy(&kasp, o_adapter, hsm_server_id.clone());
        let out_path = format!("{output_dir_path}/policies/{c_pol_name}.toml");
        c_pol.save(out_path.as_str().into()).unwrap();
        c_pol_by_c_pol_name.insert(c_pol_name.to_string(), c_pol);
    }

    // Output `cascade` commands for the user to run.
    println!("Generating '{output_dir_path}/commands.sh'...");
    let cmd_file_path = format!("{output_dir_path}/commands.sh");
    let mut cmd_file =
        File::create(cmd_file_path).expect("Should be able to write the command file");

    for c_pol_name in c_pol_by_c_pol_name.keys() {
        writeln!(
            cmd_file,
            "cp {output_dir_path}/policies/{c_pol_name}.toml {c_pol_dir}/"
        )
        .unwrap();
    }
    writeln!(cmd_file, "cascade policy reload").unwrap();

    for zone in &o_zone_list.zones {
        let addns_path = o_addns_path_by_o_zone_name.get(&zone.name);
        let Some(c_pol_name) = c_pol_name_by_o_pol_name_plus_addns_path
            .get(&(zone.policy.clone(), addns_path.cloned()))
        else {
            unreachable!()
        };

        let mut source = zone.adapters.input.adapter.path.clone();
        if let Some(o_adapter) = o_adapter_by_addns_path.get(&zone.adapters.input.adapter.path) {
            if let Some(inbound) = &o_adapter.dns.inbound {
                if let Some(rt) = &inbound.request_transfer {
                    // We only support the first source address.
                    if let Some(remote) = rt.remote.first() {
                        let port = remote.port.unwrap_or(53);
                        let ip_addr = IpAddr::from_str(&remote.address).unwrap();
                        source = format!("{ip_addr}:{port}");
                    }
                }
            }
        }

        writeln!(
            cmd_file,
            "cascade {c_cli_args} zone add --policy {c_pol_name} --source {source} {}",
            zone.name
        )
        .unwrap();

        cmd_file.flush().unwrap();
    }
    drop(cmd_file);

    println!();
    println!("Preparations complete.");
    println!();
    println!("Next steps:");
    println!("  - Stop OpenDNSSEC: ods-control stop");
    if let Some(ref pub_interfaces) = o_conf
        .signer
        .map(|s| s.listener.interfaces)
        .and_then(|i| (!i.is_empty()).then_some(i))
    {
        println!("  - Configure Cascade to publish on the same interfaces");
        println!("    as the OpenDNSSEC Signer by setting [server].servers");
        println!("    in {c_conf_toml_path} to:");
        println!();
        let servers = pub_interfaces
            .iter()
            .map(|i| format!("{}:{}", i.address, i.port))
            .collect::<Vec<String>>()
            .join(",");
        print!("      servers = [{servers}]");
    } else {
        // OpenDNSSEC was not configured to serve XFR. It must therefore have
        // been writing signed zones to files on disk.

        println!("  - Alter ")
    }
    println!("  - (optional) Configure Cascade to publish on the same ");

    Ok(())
}

fn dbg_to_file<T: std::fmt::Debug>(v: T, name: &str, dbg_dir: &str) {
    let mut f = mk_nice_io_err(
        File::create(&format!("{dbg_dir}/{name}")),
        format!("create file '{dbg_dir}/{name}' for writing"),
    );
    write!(f, "{:#?}", &v).unwrap();
}

fn mk_nice_io_err<T>(res: std::io::Result<T>, op: String) -> T {
    match res {
        Ok(v) => v,
        Err(err) => {
            let reason = match err.kind() {
                ErrorKind::NotFound => "path not found".to_string(),
                ErrorKind::PermissionDenied => "permission denied".to_string(),
                ErrorKind::AlreadyExists => "directory already exists".to_string(),
                ErrorKind::ReadOnlyFilesystem => "read-only filesystem".to_string(),
                ErrorKind::StorageFull => "no space available".to_string(),
                ErrorKind::QuotaExceeded => "quota exceeded".to_string(),
                ErrorKind::ResourceBusy => "filesystem busy".to_string(),
                other => other.to_string(),
            };
            eprintln!("ERROR: Cannot {op}: {reason}");
            std::process::exit(1);
        }
    }
}

fn process_adapter(
    adapter: &crate::schema::xml::zone_list::Adapter,
    addns_paths_to_adapters: &mut BTreeMap<String, Adapter>,
) -> Result<Option<String>, DeError> {
    match adapter._type.as_str() {
        "File" => {
            // Zone file, do not load it.
        }
        "DNS" => {
            // addns.xml, load it.
            let path = adapter.path.clone();
            if !addns_paths_to_adapters.contains_key(&path) {
                println!("Loading {path}...");
                let xml = std::fs::read_to_string(&path).unwrap();
                let adapter: Adapter = process_xml(&xml)?;
                addns_paths_to_adapters.insert(path.clone(), adapter);
            }
            return Ok(Some(path));
        }
        other => panic!("Unsupported adapter type '{other}'"),
    }
    Ok(None)
}

fn process_xml<'de, T: Deserialize<'de>>(xml: &'de str) -> Result<T, DeError> {
    quick_xml::de::from_str(xml)
}

fn create_cascade_policy(
    kasp: &crate::schema::xml::kasp::Policy,
    output: Option<&Outbound>,
    hsm_server_id: String,
) -> cascade::policy::file::Spec {
    // NOTE: OpenDNSSEC supports multiple keys per key type (KSK, ZSK, CSK)
    // per policy each having their own algorithm settings. Cascade only
    // supports one key specification per policy. Use the first key found.
    let use_csk = !kasp.keys.csks.is_empty();
    let mut algorithm = None;

    let ksk = kasp.keys.ksks.iter().next();
    if let Some(key) = ksk {
        algorithm = Some(alg_to_key_parameters(Key::Ksk(key)));
    }

    let zsk = kasp.keys.zsks.iter().next();
    if let Some(key) = zsk {
        let zsk_algorithm = Some(alg_to_key_parameters(Key::Zsk(key)));
        if zsk_algorithm != algorithm {
            panic!(
                "Unsupported: ZSK algorithm ({}) != KSK algorithm ({})",
                zsk_algorithm.unwrap(),
                algorithm.unwrap(),
            )
        }
    }

    let csk = kasp.keys.csks.iter().next();
    if let Some(key) = csk {
        let csk_algorithm = Some(alg_to_key_parameters(Key::Csk(key)));
        if csk_algorithm != algorithm {
            panic!(
                "Unsupported: CSK algorithm ({}) != KSK algorithm ({})",
                csk_algorithm.unwrap(),
                algorithm.unwrap(),
            )
        }
    }

    let mut send_notify_to = vec![];
    if let Some(output) = output {
        if let Some(notify) = &output.notify {
            for remote in &notify.remote {
                let port = remote.port.unwrap_or(53);
                let ip_addr = IpAddr::from_str(&remote.address).unwrap();
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
            hsm_server_id: Some(hsm_server_id),
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
            default_ttl: Ttl::from_secs(parse_ods_ts(&kasp.keys.ttl).try_into().unwrap()),
            auto_remove: kasp.keys.purge.is_some(), // NOTE: ODS uses a delay, Cascade does not
        },
        signer: SignerPolicy {
            serial_policy: match kasp.zone.soa.serial.serial {
                SerialEnum::counter => SignerSerialPolicy::Counter,
                SerialEnum::datecounter => SignerSerialPolicy::DateCounter,
                SerialEnum::unixtime => SignerSerialPolicy::UnixTime,
                SerialEnum::keep => SignerSerialPolicy::Keep,
            },
            sig_inception_offset: Duration::from_secs(0), // TODO
            sig_validity_time: Duration::from_secs(0),    // TODO
            sig_remain_time: Duration::from_secs(0),      // TODO
            denial: SignerDenialPolicy::NSec,             // TODO
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

    cascade::policy::file::Spec::build(&policy)
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
fn parse_ods_ts(timestamp: &str) -> u64 {
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

    let mut ts: u64 = 0;
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
) -> Option<u64> {
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
    MySQL(sqlx::MySqlConnection),
    SQLite(sqlx::SqliteConnection),
}

impl DbConn {
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
                MySqlConnection::connect(&url)
                    .await
                    .map(|c| DbConn::MySQL(c))
            }
            DatastoreEnum::sqlite(db) => {
                let url = format!("sqlite://{}", db.0);
                println!("Connecting to SQLite Enforcer database at {url}...");
                SqliteConnection::connect(&url)
                    .await
                    .map(|c| DbConn::SQLite(c))
            }
        }
    }

    async fn db_version(&mut self) -> Result<schema::db::DatabaseVersion, sqlx::Error> {
        // TODO: If we end up writing a lot of queries it might be good to
        // extract the common code into a helper function or even a proc
        // macro.
        const Q: &str = "SELECT * FROM databaseversion";
        match self {
            DbConn::MySQL(c) => sqlx::query_as(Q).fetch_one(c).await,
            DbConn::SQLite(c) => sqlx::query_as(Q).fetch_one(c).await,
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
