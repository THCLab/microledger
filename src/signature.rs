use keri::{derivation::basic::Basic, keys::PublicKey, prefix::SelfSigningPrefix};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Signatures include the cryptographic commitment of Custodians to a given Block.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
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
