use keri::{derivation::basic::Basic, keys::PublicKey, prefix::SelfSigningPrefix};

pub trait Signature {
    fn verify_with(&self, data: &[u8], pk: &[u8]) -> bool;
}

impl Signature for SelfSigningPrefix {
    fn verify_with(&self, data: &[u8], pk: &[u8]) -> bool {
        Basic::Ed25519
            .derive(PublicKey::new(pk.to_vec()))
            .verify(data, self)
            .unwrap()
    }
}
