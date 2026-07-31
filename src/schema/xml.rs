#![allow(dead_code)]

// Based on: https://github.com/opendnssec/opendnssec/blob/2.1.14/conf/conf.rnc
pub mod conf {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Configuration {
        pub repository_list: RepositoryList,
        pub common: Common,
        pub enforcer: Enforcer,
        #[serde(default)]
        pub signer: Option<Signer>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RepositoryList {
        #[serde(rename = "Repository", default)]
        pub repositories: Vec<Repository>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Repository {
        #[serde(rename = "@name")]
        pub name: String,
        pub module: String,
        pub token_label: String,
        #[serde(default, rename = "PIN")]
        pub pin: Option<String>,
        #[serde(default)]
        pub capacity: Option<usize>,
        #[serde(default)]
        pub require_backup: Option<()>,
        #[serde(default)]
        pub skip_public_key: Option<()>,
        #[serde(default)]
        pub allow_extraction: Option<()>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Common {
        #[serde(default)]
        pub logging: Option<Logging>,
        pub policy_file: String,
        pub zone_list_file: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Logging {
        #[serde(default)]
        pub verbosity: Option<usize>,
        #[serde(default)]
        pub syslog: Option<Syslog>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Syslog {
        pub facility: SyslogFacility,
    }

    #[derive(Debug, Deserialize)]
    #[allow(non_camel_case_types)]
    pub enum SyslogFacility {
        kern,
        user,
        mail,
        daemon,
        auth,
        lpr,
        news,
        uucp,
        cron,
        local0,
        local1,
        local2,
        local3,
        local4,
        local5,
        local6,
        local7,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Enforcer {
        #[serde(default)]
        pub privileges: Option<Privileges>,
        pub datastore: Datastore,
        #[serde(default)]
        pub manual_key_generation: Option<()>,
        #[serde(default = "Enforcer::default_automatic_key_generation_period")]
        pub automatic_key_generation_period: String,
        #[serde(default)]
        pub rollover_notification: Option<String>,
        #[serde(default)]
        pub delegation_signer_submit_command: Option<String>,
        #[serde(default)]
        pub delegation_signer_retract_command: Option<String>,
        #[serde(default)]
        pub pid_file: Option<String>,
        #[serde(default)]
        pub socket_file: Option<String>,
        #[serde(default = "Enforcer::default_working_directory")]
        pub working_directory: String,
        #[serde(default = "Enforcer::default_worker_threads")]
        pub worker_threads: usize,
    }

    impl Enforcer {
        fn default_automatic_key_generation_period() -> String {
            // From OpenDNSSEC conf.rnc
            "P1Y".to_string()
        }

        fn default_working_directory() -> String {
            // OpenDNSSEC conf.rnc defines this as
            // "$(localstatedir)/opendnssec/tmp" but we don't
            // know what $(localstatedir) is. Also, note that
            // parse_conf_zonelist_filename() uses a different
            // default determined at compilation time called
            // OPENDNSSEC_ENFORCER_WORKINGDIR which is defined as
            // "${localstatedir}/opendnssec/enforcer" and in my
            // tests evaluating to /var/opendnssec/enforcer
            "/var/opendnssec/enforcer".to_string()
        }

        fn default_worker_threads() -> usize {
            // From OpenDNSSEC conf.rnc
            4
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Signer {
        pub privileges: Option<Privileges>,
        #[serde(default = "Signer::default_working_directory")]
        pub working_directory: String,
        #[serde(default)]
        pub worker_threads: Option<usize>,
        #[serde(default)]
        pub signer_threads: Option<usize>,
        #[serde(default)]
        pub listener: Listener,
        #[serde(default)]
        pub notify_command: Option<String>,
    }

    impl Signer {
        fn default_working_directory() -> String {
            // From OpenDNSSEC conf.rc
            "$(localstatedir)/opendnssec/tmp".to_string()
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Privileges {
        #[serde(default)]
        pub user: Option<String>,
        #[serde(default)]
        pub group: Option<String>,
        #[serde(default)]
        pub directory: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Datastore {
        #[serde(rename = "$value")]
        pub datastore: DatastoreEnum,
    }

    #[derive(Debug, Deserialize)]
    #[allow(non_camel_case_types)]
    pub enum DatastoreEnum {
        #[serde(rename = "MySQL")]
        mysql(Mysql),
        #[serde(rename = "SQLite")]
        sqlite(Sqlite),
        #[serde(rename = "Test")]
        test(String),
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Listener {
        #[serde(default)]
        pub interfaces: Vec<Interface>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Interface {
        pub address: String,
        pub port: u16,
    }

    impl Interface {
        fn new(address: String, port: u16) -> Self {
            Self { address, port }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Mysql {
        #[serde(default)]
        pub host: Option<Host>,
        pub database: String,
        pub username: String,
        pub password: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Host {
        #[serde(rename = "@port", default = "Host::default_port")]
        pub port: u16,
        #[serde(default = "Host::default_address")]
        pub address: String,
    }

    impl Host {
        fn default_port() -> u16 {
            // From OpenDNSSEC conf.rnc
            3306
        }

        fn default_address() -> String {
            // From OpenDNSSEC conf.rnc
            "127.0.0.1".to_string()
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct Sqlite(pub String);
}

// Based on: https://github.com/opendnssec/opendnssec/blob/2.1.14/conf/zonelist.rnc
pub mod zone_list {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ZoneList {
        #[serde(default, rename = "$value")]
        pub zones: Vec<Zone>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Zone {
        #[serde(rename = "@name")]
        pub name: String,
        pub policy: String,
        pub signer_configuration: String,
        pub adapters: Adapters,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Adapters {
        pub input: Input,
        pub output: Output,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Input {
        #[serde(rename = "$value")]
        pub adapter: Adapter,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Output {
        #[serde(rename = "$value")]
        pub adapter: Adapter,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    #[allow(non_camel_case_types)]
    pub enum AdapterType {
        #[serde(rename = "$value")]
        adfile(File),
        #[serde(rename = "Adapter")]
        adother(Adapter),
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct File {
        #[serde(rename = "$value")]
        value: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Adapter {
        #[serde(rename = "@type")]
        pub _type: String,
        #[serde(rename = "$value")]
        pub path: String,
    }
}

// Based on: https://github.com/opendnssec/opendnssec/blob/2.1.14/conf/addns.rnc
pub mod addns {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Adapter {
        #[serde(rename = "DNS")]
        pub dns: Dns,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Dns {
        #[serde(rename = "TSIG")]
        pub tsig: Vec<Tsig>,
        pub inbound: Option<Inbound>,
        pub outbound: Option<Outbound>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Tsig {
        pub name: String,
        pub algorithm: String,
        pub secret: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Inbound {
        pub request_transfer: Option<RequestTransfer>,
        pub allow_notify: Option<AllowNotify>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RequestTransfer {
        #[serde(rename = "$value")]
        pub remote: Vec<Remote>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AllowNotify {
        #[serde(rename = "$value")]
        pub remote: Vec<Peer>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Outbound {
        pub provide_transfer: Option<ProvideTransfer>,
        pub notify: Option<Notify>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ProvideTransfer {
        #[serde(rename = "$value")]
        pub remote: Vec<Peer>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Notify {
        #[serde(rename = "$value")]
        pub remote: Vec<Remote>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Remote {
        pub address: String,
        pub port: Option<u16>,
        pub key: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Peer {
        pub prefix: Option<String>,
        pub key: Option<String>,
    }
}

// Based on: https://github.com/opendnssec/opendnssec/blob/2.1.14/conf/kasp.rnc
pub mod kasp {
    use serde::Deserialize;

    use crate::schema::xml::common::{Denial, Signatures, ZoneSoa};

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    #[allow(clippy::upper_case_acronyms)]
    pub struct KASP {
        #[serde(rename = "$value", default)]
        pub policies: Vec<Policy>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Policy {
        #[serde(rename = "@name")]
        pub name: String,
        pub passthrough: Option<()>,
        pub description: String,
        pub signatures: Signatures,
        pub denial: Denial,
        pub keys: Keys,
        pub zone: Zone,
        pub parent: Parent,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Keys {
        #[serde(rename = "TTL")]
        pub ttl: String,
        pub retire_safety: String,
        pub publish_safety: String,
        pub share_keys: Option<()>,
        pub purge: Option<String>,
        #[serde(rename = "KSK", default)]
        pub ksks: Vec<Ksk>,
        #[serde(rename = "ZSK", default)]
        pub zsks: Vec<Zsk>,
        #[serde(rename = "CSK", default)]
        pub csks: Vec<Csk>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Parent {
        pub propagation_delay: PropagationDelay,
        #[serde(rename = "DS")]
        pub ds: Ds,
        #[serde(rename = "SOA")]
        pub soa: Soa,
        pub registration_delay: Option<RegistrationDelay>,
    }

    // #[derive(Debug, Deserialize)]
    // #[serde(rename_all = "PascalCase")]
    // pub struct AnyKey {
    //     pub algorithm: Algorithm,
    //     pub lifetime: String,
    //     pub repository: String,
    //     pub standby: Option<usize>,
    //     pub manual_rollover: Option<()>,
    // }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "PascalCase")]
    pub struct Algorithm {
        #[serde(rename = "@length")]
        // https://github.com/NLnetLabs/ods2cascade/issues/59: While
        // https://github.com/opendnssec/opendnssec/blob/2.1.14/conf/kasp.rnc
        // specifies that length is mandatory, the actual OpenDNSSEC kasp
        // XML parsing code does not enforce the schema but instead uses a
        // default length of 0.
        #[serde(default = "Algorithm::default_algorithm_length")]
        pub length: String,
        #[serde(rename = "$text")]
        pub value: String, // TODO: should be a u8
    }

    impl Algorithm {
        fn default_algorithm_length() -> String {
            // "0" according to https://github.com/opendnssec/opendnssec/blob/1f1bea259f55ccf3841184b3ba504a5d1f4639b8/enforcer/src/db/policy_key_ext.c#L339
            "0".to_string()
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Ksk {
        // #[serde(flatten)]
        // pub anykey: AnyKey,
        pub algorithm: Algorithm,
        pub lifetime: String,
        pub repository: String,
        pub standby: Option<usize>,
        pub manual_rollover: Option<()>,
        pub ksk_roll_type: Option<KskRollType>,
        #[serde(rename = "RFC5011")]
        pub rfc5011: Option<()>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Zsk {
        // #[serde(flatten)]
        // pub anykey: AnyKey,
        pub algorithm: Algorithm,
        pub lifetime: String,
        pub repository: String,
        pub standby: Option<usize>,
        pub manual_rollover: Option<()>,
        pub zsk_roll_type: Option<ZskRollType>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Csk {
        // #[serde(flatten)]
        // pub anykey: AnyKey,
        pub algorithm: Algorithm,
        pub lifetime: String,
        pub repository: String,
        pub standby: Option<usize>,
        pub manual_rollover: Option<()>,
        pub csk_roll_type: Option<CskRollType>,
        #[serde(rename = "RFC5011")]
        pub rfc5011: Option<()>,
    }

    #[derive(Debug, Deserialize)]
    pub enum KskRollType {
        KskDoubleRRset,
        KskDoubleDS,
        KskDoubleSignature,
    }

    #[derive(Debug, Deserialize)]
    #[allow(clippy::enum_variant_names)]
    pub enum ZskRollType {
        ZskDoubleSignature,
        ZskPrePublication,
        ZskDoubleRRsig,
    }

    #[derive(Debug, Deserialize)]
    pub enum CskRollType {
        CskDoubleRRset,
        CskSingleSignature,
        CskDoubleDS,
        CskDoubleSignature,
        CskPrePublication,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Zone {
        pub propagation_delay: String, // TODO
        #[serde(rename = "SOA")]
        pub soa: ZoneSoa,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Soa {
        #[serde(rename = "TTL")]
        pub ttl: String,
        pub minimum: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Ds {
        #[serde(rename = "TTL")]
        pub ttl: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct PropagationDelay {
        #[serde(rename = "$value")]
        pub duration: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct RegistrationDelay {
        #[serde(rename = "$value")]
        pub duration: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct Partial {
        #[serde(rename = "$value")]
        pub empty: (),
    }
}

// Based on: https://github.com/opendnssec/opendnssec/blob/2.1.14/conf/signconf.rnc
pub mod signconf {
    use serde::Deserialize;

    use crate::schema::xml::common::{Denial, Signatures, ZoneSoa};

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SignerConfiguration {
        pub zone: Zone,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Zone {
        #[serde(rename = "@name")]
        pub name: String,
        #[serde(default)]
        pub passthrough: Option<()>,
        pub signatures: Signatures,
        pub denial: Denial,
        pub keys: Keys,
        #[serde(rename = "SOA")]
        pub soa: ZoneSoa,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Keys {
        #[serde(rename = "TTL")]
        pub ttl: String,
        #[serde(rename = "Key")]
        pub keys: Vec<Key>,
        #[serde(default)]
        pub signature_resource_record: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Key {
        pub flags: Flags,
        pub algorithm: Algorithm,
        #[serde(default)]
        pub locator: Option<String>,
        #[serde(default)]
        pub resource_record: Option<String>,
        #[serde(default, rename = "KSK")]
        pub ksk: Option<()>,
        #[serde(default, rename = "ZSK")]
        pub zsk: Option<()>,
        #[serde(default)]
        pub publish: Option<()>,
        #[serde(default)]
        pub deactivate: Option<()>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Flags {
        #[serde(rename = "$text")]
        pub value: String, // TODO: should be a u16
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Algorithm {
        #[serde(rename = "$text")]
        pub value: String, // TODO: should be a u8
    }
}

pub mod common {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Signatures {
        pub resign: String,
        pub refresh: String,
        pub validity: Validity,
        pub jitter: String,
        pub inception_offset: String,
        #[serde(rename = "MaxZoneTTL")]
        pub max_zone_ttl: Option<MaxZoneTTL>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Validity {
        pub default: String,
        pub denial: String,
        #[serde(default)]
        pub keyset: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Denial {
        #[serde(rename = "$value")]
        pub denial: DenialEnum,
    }

    #[derive(Debug, Deserialize)]
    #[allow(non_camel_case_types)]
    pub enum DenialEnum {
        #[serde(rename = "NSEC")]
        nsec(Nsec),
        #[serde(rename = "NSEC3")]
        nsec3(Nsec3),
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Nsec;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Nsec3 {
        #[serde(rename = "TTL")]
        pub ttl: Option<String>,
        pub opt_out: Option<()>,
        pub resalt: String,
        pub hash: Hash,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Hash {
        pub algorithm: u8,
        pub iterations: u16,
        pub salt: Salt,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Salt {
        #[serde(rename = "@length")]
        pub length: String, // TODO: should actually be u8
        #[serde(rename = "$value", default)]
        pub salt: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct MaxZoneTTL {
        #[serde(rename = "$value")]
        pub duration: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ZoneSoa {
        #[serde(rename = "TTL")]
        pub ttl: String,
        pub minimum: String,
        #[serde(rename = "Serial")]
        pub serial: Serial,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Serial {
        #[serde(rename = "$text")]
        pub serial: SerialEnum,
    }

    #[derive(Debug, Deserialize)]
    #[allow(non_camel_case_types)]
    pub enum SerialEnum {
        counter,
        datecounter,
        unixtime,
        keep,
    }
}
