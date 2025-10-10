use std::usize;

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
    #[serde(default)]
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
enum SyslogFacility {
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
    pub privs: Option<Privileges>,
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
        // From OpenDNSSEC conf.rc
        "$(localstatedir)/opendnssec/tmp".to_string()
    }

    fn default_worker_threads() -> usize {
        // From OpenDNSSEC conf.rnc
        4
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Signer {
    privs: Option<Privileges>,
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
enum DatastoreEnum {
    #[serde(rename = "MySQL")]
    mysql(Mysql),
    #[serde(rename = "SQLite")]
    sqlite(Sqlite),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Listener {
    #[serde(default)]
    pub interfaces: Vec<Interface>,
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            // From OpenDNSSEC conf.rnc
            interfaces: vec![Interface::new("".to_string(), 15534)],
        }
    }
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
