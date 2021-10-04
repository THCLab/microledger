use keri::prefix::BasicPrefix;

use crate::{error::Error, signature::Signature};

pub trait ControlingIdentifier {
    fn check_signatures<S: Signature>(&self, msg: &[u8], signatures: &[S]) -> Result<bool, Error>;
}

impl ControlingIdentifier for BasicPrefix {
    fn check_signatures<S: Signature>(&self, msg: &[u8], signatures: &[S]) -> Result<bool, Error> {
        Ok(signatures
            .iter()
            .any(|s| s.verify_with(msg, &self.public_key.key()).unwrap()))
    }
}
