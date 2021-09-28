use keri::{
    derivation::basic::Basic,
    keys::PublicKey,
    prefix::{BasicPrefix, Prefix},
};

use serde::{Deserialize, Serialize};

use crate::signature::Signature;

pub trait ControlingIdentifier {
    fn check_signatures<S: Signature>(&self, msg: &[u8], signatures: &[S]) -> bool;
}

#[derive(Serialize, Deserialize)]
pub struct Rules {
    public_keys: Vec<BasicPrefix>,
}

impl Rules {
    pub fn new(keys_vec: Vec<Vec<u8>>) -> Self {
        let keys = keys_vec
            .into_iter()
            .map(|key| Basic::Ed25519.derive(PublicKey::new(key)))
            .collect();
        Rules { public_keys: keys }
    }
}

impl ControlingIdentifier for Rules {
    fn check_signatures<S: Signature>(&self, msg: &[u8], signatures: &[S]) -> bool {
        // any of keys can verify signatures
        self.public_keys
            .iter()
            .map(|pk| {
                signatures
                    .iter()
                    .map(|s| s.verify_with(msg, &pk.derivative()))
                    .any(|e| e)
            })
            .all(|e| e)
    }
}
