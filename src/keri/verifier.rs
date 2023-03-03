use std::sync::Arc;

use keri::{database::SledEventDatabase, processor::validator::EventValidator};

use crate::{microledger::Result, verifier::Verifier};

use super::KeriSignature;

pub struct KeriVerifier(EventValidator);

impl Verifier for KeriVerifier {
    type Signature = KeriSignature;

    fn verify(&self, data: &[u8], s: Vec<Self::Signature>) -> Result<bool> {
        Ok(s.into_iter().all(|sig| self.0.verify(data, &sig).is_ok()))
    }
}

impl KeriVerifier {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        KeriVerifier(EventValidator::new(db))
    }
}
