use serde::Serialize;

use crate::error::Error;
use crate::Serialization;
use crate::{
    block::{Block, SignedBlock},
    controling_identifiers::ControlingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    seal_provider::SealProvider,
    seals::Seal,
    signature::Signature,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default)]
pub struct MicroLedger<I, D, C, P, S>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    P: SealProvider + Serialize,
    S: Signature + Serialize,
{
    pub blocks: Vec<SignedBlock<I, C, D, S, P>>,
}

impl<I, D, C, P, S> MicroLedger<I, D, C, P, S>
where
    I: Seal + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    P: SealProvider + Serialize,
    S: Signature + Serialize,
{
    pub fn new() -> Self {
        MicroLedger { blocks: vec![] }
    }

    pub fn pre_anchor_block(
        &self,
        attachements: Vec<I>,
        seals_prov: P,
        rules: C,
    ) -> Block<I, D, C, P>
    where
        I: Seal + Serialize + Clone,
        D: DigitalFingerprint + Serialize,
        C: ControlingIdentifier + Serialize + Clone,
        P: SealProvider + Serialize,
        S: Signature + Serialize,
    {
        let prev = self
            .blocks
            .last()
            .map(|sb| D::derive(&Serialization::serialize(&sb.block)));

        Block::new(attachements, prev, rules, seals_prov)
    }

    fn get_last_block(&self) -> Option<&Block<I, D, C, P>> {
        self.blocks.last().map(|last| &last.block)
    }

    fn current_rules(&self) -> Result<Option<C>> {
        Ok(self.get_last_block().map(|block| block.rules.clone()))
    }

    pub fn anchor(&mut self, block: SignedBlock<I, C, D, S, P>) -> Result<()> {
        let last = self.get_last_block();
        // Checks block binding and signatures.
        if block.check_block(last)? && block.verify(self.current_rules()?)? {
            Ok(self.blocks.push(block))
        } else {
            Err(Error::MicroError("Wrong block".into()))
        }
    }
}
