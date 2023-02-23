use std::{fmt::Display, str::FromStr};

use cesrox::primitives::CesrPrimitive;
use keri::prefix::{BasicPrefix, SelfSigningPrefix};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Error;

/// Signatures include the cryptographic commitment of Custodians to a given Block.
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    SelfSigning(SelfSigningPrefix),
}

impl Signature {
    pub fn verify_with(&self, data: &[u8], pk: &BasicPrefix) -> Result<bool, Error> {
        match self {
            Self::SelfSigning(prefix) => pk
                .verify(data, prefix)
                .map_err(|_| Error::SignatureVerificationError),
        }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signature::SelfSigning(id) => write!(f, "A{}", id.to_str()),
        }
    }
}

impl FromStr for Signature {
    type Err = keri::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).zip(s.get(1..)) {
            Some(("A", id)) => Ok(Self::SelfSigning(id.parse()?)),
            _ => Err(keri::error::Error::DeserializeError(
                "Unknown prefix".into(),
            )),
        }
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
