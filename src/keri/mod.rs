use std::{convert::TryInto, sync::Arc};

use keri::prefix::IdentifierPrefix;

use crate::{
    error::Error, microledger::MicroLedger, verifier::Verifier, Identifier, Result, Signature,
};

pub mod signed_block;
#[cfg(test)]
mod tests;
pub mod verifier;

pub type KeriSignature = keri::event_message::signature::Signature;

impl Identifier for IdentifierPrefix {}

impl Signature for KeriSignature {
    type Identifier = IdentifierPrefix;

    fn get_signer(&self) -> Option<Self::Identifier> {
        self.get_signer()
    }
}

impl<V> MicroLedger<KeriSignature, V, IdentifierPrefix>
where
    V: Verifier<Signature = KeriSignature>,
{
    pub fn new_from_cesr(stream: &[u8], verifier: Arc<V>) -> Result<Self> {
        let (_rest, parsed_stream) = cesrox::parse_many(stream).map_err(|_e| Error::CesrError)?;
        let mut microledger = MicroLedger::new(verifier);
        parsed_stream
            .into_iter()
            .try_for_each(|pd| microledger.append_block(pd.try_into()?))?;
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
