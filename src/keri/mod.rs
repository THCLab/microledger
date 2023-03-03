use std::sync::Arc;

use keri::prefix::IdentifierPrefix;

use crate::{
    microledger::{MicroLedger, Result},
    verifier::Verifier,
    Identifier,
};

pub mod signed_block;
#[cfg(test)]
mod tests;
pub mod verifier;

pub type KeriSignature = keri::event_message::signature::Signature;

impl Identifier for IdentifierPrefix {}

impl<V> MicroLedger<KeriSignature, V, IdentifierPrefix>
where
    V: Verifier<Signature = KeriSignature>,
{
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
            .flat_map(|bl| bl.to_cesr().unwrap())
            .collect())
    }
}
