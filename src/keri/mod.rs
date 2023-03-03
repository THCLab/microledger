use std::sync::Arc;

use crate::{
    microledger::{MicroLedger, Result},
    verifier::Verifier,
};

use self::{controlling_identifier::ControllingIdentifier, signature::KeriSignature};

pub mod controlling_identifier;
pub mod signature;
pub mod signed_block;
pub mod verifier;

#[cfg(feature = "keri")]
impl<V: Verifier<Signature = KeriSignature>> MicroLedger<KeriSignature, V, ControllingIdentifier> {
    pub fn new_from_cesr(stream: &[u8], verifier: Arc<V>) -> Result<Self> {
        let (_rest, parsed_stream) = cesrox::parse_many(stream).unwrap();
        let mut microledger = MicroLedger::new(verifier);
        parsed_stream
            .into_iter()
            .for_each(|pd| microledger.append_block(pd.into()).unwrap());
        Ok(microledger)
    }

    pub fn to_cesr(&self) -> Result<Vec<u8>> {
        Ok(self
            .blocks
            .iter()
            .map(|bl| bl.to_cesr().unwrap())
            .flatten()
            .collect())
    }
}
