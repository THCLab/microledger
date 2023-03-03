use std::sync::Arc;

use crate::{verifier::Verifier, microledger::{MicroLedger, Result}};

use self::{signature::KeriSignature, controlling_identifier::ControllingIdentifier};


pub mod verifier;
pub mod signed_block;
pub mod signature;
pub mod controlling_identifier;

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
