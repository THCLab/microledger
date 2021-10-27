use std::{convert::TryFrom, str::FromStr};

use keri::{
    derivation::basic::Basic,
    keys::PublicKey,
    prefix::{Prefix, SelfSigningPrefix},
};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Signatures include the cryptographic commitment of Custodians to a given Block.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(try_from = "String", into = "String")]
pub enum Signature {
    SelfSigning(SelfSigningPrefix),
}

impl Signature {
    pub fn verify_with(&self, data: &[u8], pk: &[u8]) -> Result<bool, Error> {
        match self {
            Self::SelfSigning(prefix) => Basic::Ed25519
                .derive(PublicKey::new(pk.to_vec()))
                .verify(data, prefix)
                .map_err(Error::SignatureVerificationError),
        }
    }
}

impl From<Signature> for String {
    fn from(val: Signature) -> Self {
        match val {
            Signature::SelfSigning(id) => format!("A{}", id.to_str()),
        }
    }
}

impl TryFrom<String> for Signature {
    type Error = keri::error::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match (value.get(..1), value.get(1..)) {
            (Some("A"), Some(id)) => Ok(Self::SelfSigning(SelfSigningPrefix::from_str(id)?)),
            _ => Err(keri::error::Error::DeserializeError(
                "unknown prefix".into(),
            )),
        }
    }
}
