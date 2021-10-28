use std::{fmt::Display, str::FromStr};

use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A digital fingerprint include the cryptographically derived unique fingerprint of a given block.
/// The digital fingerprint is a result of a one-way hash function operation on that block.
#[derive(Clone, Debug, PartialEq)]
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

impl Display for DigitalFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigitalFingerprint::SelfAddressing(id) => write!(f, "A{}", id),
        }
    }
}

impl FromStr for DigitalFingerprint {
    type Err = said::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).zip(s.get(1..)) {
            Some(("A", id)) => Ok(Self::SelfAddressing(id.parse()?)),
            _ => Err(said::error::Error::DeserializationError(
                "Unknown prefix".into(),
            )),
        }
    }
}

impl Serialize for DigitalFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DigitalFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
