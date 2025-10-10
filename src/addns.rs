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
