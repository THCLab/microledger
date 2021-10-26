use keri::prefix::BasicPrefix;
use serde::{Deserialize, Serialize};

use crate::{error::Error, signature::Signature};

/// Controlling identifier describes control authority over the Microledger in a given block.
/// Control _MAY_ be established for single or multiple identifiers through the multisig feature.
/// Controlling identifiers can be anything that is considered identifiable within given network,
/// ie. `Public Key`, `DID`, `KERI` prefix and so on.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
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
