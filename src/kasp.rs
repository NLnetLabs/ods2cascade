use std::usize;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KASP {
    #[serde(rename = "$value")]
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
