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
