use keri::{derivation::basic::Basic, keys::PublicKey, prefix::SelfSigningPrefix};

use crate::error::Error;

pub trait Signature {
    fn verify_with(&self, data: &[u8], pk: &[u8]) -> Result<bool, Error>;
}

impl Signature for SelfSigningPrefix {
    fn verify_with(&self, data: &[u8], pk: &[u8]) -> Result<bool, Error> {
        Basic::Ed25519
            .derive(PublicKey::new(pk.to_vec()))
            .verify(data, self)
            .map_err(|e| Error::SignatureVerificationError(e))
    }
}
