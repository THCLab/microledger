use std::{convert::TryFrom, str::FromStr};

use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};
use serde::{Deserialize, Serialize};

/// A digital fingerprint include the cryptographically derived unique fingerprint of a given block.
/// The digital fingerprint is a result of a one-way hash function operation on that block.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(try_from = "String", into = "String")]
pub enum DigitalFingerprint {
    SelfAddressing(SelfAddressingPrefix),
}

impl DigitalFingerprint {
    pub fn verify_binding(&self, data: &[u8]) -> bool {
        match self {
            Self::SelfAddressing(prefix) => prefix.verify_binding(data),
        }
    }

    pub fn derive(data: &[u8]) -> Self {
        Self::SelfAddressing(SelfAddressing::Blake3_256.derive(data))
    }
}

impl From<DigitalFingerprint> for String {
    fn from(val: DigitalFingerprint) -> Self {
        match val {
            DigitalFingerprint::SelfAddressing(id) => format!("A{}", id),
        }
    }
}

impl TryFrom<String> for DigitalFingerprint {
    type Error = said::error::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match (value.get(..1), value.get(1..)) {
            (Some("A"), Some(id)) => Ok(Self::SelfAddressing(SelfAddressingPrefix::from_str(id)?)),
            _ => Err(said::error::Error::DeserializationError(
                "Unknown prefix".into(),
            )),
        }
    }
}
