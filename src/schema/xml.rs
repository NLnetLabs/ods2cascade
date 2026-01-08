#![allow(dead_code)]

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
        #[serde(default = "Repository::default_capacity")]
        pub capacity: usize,
        #[serde(default)]
        pub require_backup: Option<()>,
        #[serde(default)]
        pub skip_public_key: Option<()>,
        #[serde(default)]
        pub allow_extraction: Option<()>,
    }

    impl Repository {
        fn default_capacity() -> usize {
            // INFINITE according to OpenDNSSEC conf.rnc
            usize::MAX
        }
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
        #[serde(default = "Signer::default_worker_threads")]
        pub worker_threads: usize,
        #[serde(default = "Signer::default_signer_threads")]
        pub signer_threads: usize,
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

        fn default_worker_threads() -> usize {
            // From OpenDNSSEC conf.rnc
            4
        }

        fn default_signer_threads() -> usize {
            // From OpenDNSSEC conf.rnc
            4
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Privileges {
        pub user: Option<String>,
        pub group: Option<String>,
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

pub mod kasp {
    use serde::Deserialize;

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

    // #[derive(Debug, Deserialize)]
    // #[serde(rename_all = "PascalCase")]
    // pub struct AnyKey {
    //     pub algorithm: Algorithm,
    //     pub lifetime: String,
    //     pub repository: String,
    //     pub standby: Option<usize>,
    //     pub manual_rollover: Option<()>,
    // }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Algorithm {
        #[serde(rename = "@length")]
        pub length: String, // TODO: should actually be usize
        #[serde(rename = "$text")]
        pub value: String, // TODO: should be a u8
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
    pub struct ZoneSoa {
        #[serde(rename = "TTL")]
        pub ttl: String,
        pub minimum: String,
        #[serde(rename = "Serial")]
        pub serial: Serial,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Ds {
        #[serde(rename = "TTL")]
        pub ttl: String,
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

    #[derive(Debug, Deserialize)]
    pub struct MaxZoneTTL {
        #[serde(rename = "$value")]
        pub duration: String,
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
