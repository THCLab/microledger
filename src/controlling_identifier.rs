use std::{convert::TryFrom, str::FromStr};

use keri::prefix::{BasicPrefix, Prefix};
use serde::{Deserialize, Serialize};

use crate::{error::Error, signature::Signature};

/// Controlling identifier describes control authority over the Microledger in a given block.
/// Control _MAY_ be established for single or multiple identifiers through the multisig feature.
/// Controlling identifiers can be anything that is considered identifiable within given network,
/// ie. `Public Key`, `DID`, `KERI` prefix and so on.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(into = "String", try_from = "String")]
pub enum ControllingIdentifier {
    Basic(BasicPrefix),
}

impl ControllingIdentifier {
    pub fn check_signatures(&self, msg: &[u8], signatures: &[Signature]) -> Result<bool, Error> {
        match self {
            Self::Basic(id) => Ok(signatures
                .iter()
                .any(|s| s.verify_with(msg, &id.public_key.key()).unwrap())),
        }
    }
}

impl From<ControllingIdentifier> for String {
    fn from(val: ControllingIdentifier) -> Self {
        match val {
            ControllingIdentifier::Basic(id) => format!("A{}", id.to_str()),
        }
    }
}

impl TryFrom<String> for ControllingIdentifier {
    type Error = keri::error::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match (value.get(..1), value.get(1..)) {
            (Some("A"), Some(id)) => Ok(Self::Basic(BasicPrefix::from_str(id)?)),
            _ => Err(keri::error::Error::DeserializeError(
                "Unknown prefix".into(),
            )),
        }
    }
}
