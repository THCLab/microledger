use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};
use serde::{Deserialize, Serialize};

/// A digital fingerprint include the cryptographically derived unique fingerprint of a given block.
/// The digital fingerprint is a result of a one-way hash function operation on that block.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum DigitalFingerprint {
    SelfAddressing(SelfAddressingPrefix),
}

impl DigitalFingerprint {
    pub fn verify_binding(&self, _data: &[u8]) -> bool {
        match self {
            Self::SelfAddressing(_prefix) => {
                unimplemented!();
            }
        }
    }

    pub fn derive(data: &[u8]) -> Self {
        Self::SelfAddressing(SelfAddressing::Blake3_256.derive(data))
    }
}
