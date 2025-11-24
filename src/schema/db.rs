#![allow(dead_code)]

pub mod zone {
    #[derive(Debug, sqlx::FromRow)]
    #[sqlx(rename_all = "camelCase")]
    pub struct Zone {
        pub id: u64,
        pub name: String,
        pub policy_id: u64,
        pub signconf_needs_writing: bool,
        pub signconf_path: String,
        pub input_adapter_type: String,
        pub input_adapter_uri: String,
        pub output_adapter_type: String,
        pub output_adapter_uri: String,
    }
}

pub mod policy {
    #[derive(Debug, sqlx::FromRow)]
    #[sqlx(rename_all = "camelCase")]
    pub struct Policy {
        pub id: u64,
        pub name: String,
        pub passthrough: bool,
        pub description: String,
        #[sqlx(flatten)]
        pub signatures: Signatures,
        #[sqlx(flatten)]
        pub denial: Denial,
        #[sqlx(flatten)]
        pub keys: Keys,
        #[sqlx(flatten)]
        pub zone: Zone,
        #[sqlx(flatten)]
        pub parent: Parent,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Signatures {
        #[sqlx(rename = "signaturesResign")]
        pub resign: u32,
        #[sqlx(rename = "signaturesRefresh")]
        pub refresh: u32,
        #[sqlx(flatten)]
        pub validity: Validity,
        #[sqlx(rename = "signaturesJitter")]
        pub jitter: u32,
        #[sqlx(rename = "signaturesInceptionOffset")]
        pub inception_offset: u32,
        #[sqlx(rename = "signaturesMaxZoneTtl")]
        pub max_zone_ttl: u32,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Denial {
        /// 0  - NSEC
        /// 1? - NSEC3
        #[sqlx(rename = "denialType")]
        pub _type: i32,
        #[sqlx(rename = "denialOptout")]
        pub opt_out: bool,
        #[sqlx(rename = "denialTtl")]
        pub ttl: u32,
        #[sqlx(rename = "denialResalt")]
        pub resalt: u32,
        #[sqlx(rename = "denialAlgorithm")]
        pub algorithm: u32,
        #[sqlx(rename = "denialIterations")]
        pub iterations: u32,
        #[sqlx(rename = "denialSaltLength")]
        pub salt_length: u32,
        #[sqlx(rename = "denialSalt")]
        pub salt: String,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Validity {
        #[sqlx(rename = "signaturesValidityDefault")]
        pub default: u32,
        #[sqlx(rename = "signaturesValidityDenial")]
        pub denial: u32,
        #[sqlx(rename = "signaturesValidityKeyset", default)]
        pub keyset: Option<u32>,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Keys {
        #[sqlx(rename = "keysTtl")]
        ttl: u32,
        #[sqlx(rename = "keysRetireSafety")]
        retire_safety: u32,
        #[sqlx(rename = "keysPublishSafety")]
        publish_safety: u32,
        #[sqlx(rename = "keysShared")]
        share_keys: bool,
        #[sqlx(rename = "keysPurgeAfter")]
        purge: u32,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Zone {
        #[sqlx(rename = "zonePropagationDelay")]
        pub propagation_delay: u32,
        #[sqlx(flatten)]
        pub soa: ZoneSoa,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct ZoneSoa {
        #[sqlx(rename = "zoneSoaTtl")]
        pub ttl: u32,
        #[sqlx(rename = "zoneSoaMinimum")]
        pub minimum: u32,
        #[sqlx(rename = "zoneSoaSerial")]
        pub serial: u32,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Parent {
        #[sqlx(rename = "parentPropagationDelay")]
        pub propagation_delay: u32,
        #[sqlx(flatten)]
        pub ds: Ds,
        #[sqlx(flatten)]
        pub soa: Soa,
        #[sqlx(rename = "parentRegistrationDelay")]
        pub registration_delay: u32,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Ds {
        #[sqlx(rename = "parentDsTtl")]
        pub ttl: u32,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct Soa {
        #[sqlx(rename = "parentSoaTtl")]
        pub ttl: u32,
        #[sqlx(rename = "parentSoaMinimum")]
        pub minimum: u32,
    }

    #[derive(Debug, sqlx::FromRow)]
    #[sqlx(rename_all = "camelCase")]
    pub struct Key {
        pub id: u64,
        pub policy_id: u64,
        pub role: u32,
        pub algorithm: u32,
        pub bits: u32,
        pub lifetime: u32,
        pub repository: String,
        pub standby: u32,
        pub manual_rollover: bool,
        pub rfc5011: bool,
        pub minimize: u32, // relates to Ksk/Zsk/CskRollType in KASP.xml
    }
}

#[derive(Debug, sqlx::FromRow)]
#[sqlx(rename_all = "camelCase")]
pub struct DatabaseVersion {
    pub id: u64,
    pub rev: u32,
    pub version: u32,
}
