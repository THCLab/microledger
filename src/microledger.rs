use serde::Serialize;

use crate::Serialization;
use crate::{
    block::{Block, SignedBlock},
    controling_identifiers::ControlingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    seal_provider::SealProvider,
    seals::Seal,
    signature::Signature,
};

#[derive(Default)]
pub struct MicroLedger<I, D, C, P, S>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize,
    P: SealProvider + Serialize,
    S: Signature + Serialize,
{
    pub blocks: Vec<SignedBlock<I, C, D, S, P>>,
}

impl<I, D, C, P, S> MicroLedger<I, D, C, P, S>
where
    I: Seal + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize,
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
        C: ControlingIdentifier + Serialize,
        P: SealProvider + Serialize,
        S: Signature + Serialize,
    {
        let seal = attachements.first().unwrap();
        let prev = if self.blocks.is_empty() {
            None
        } else {
            Some(D::derive(&Serialization::serialize(
                &self.blocks.last().unwrap().block,
            )))
        };
        Block::new(seal.to_owned(), prev, rules, seals_prov)
    }

    pub fn anchor(&mut self, block: SignedBlock<I, C, D, S, P>) {
        match self.blocks.last() {
            Some(last_block) => {
                if last_block.block.append(&block) {
                    self.blocks.push(block);
                } else {
                    println!("Wrong block")
                    // wrong block
                }
            }
            None => {
                // no previous blocks. should be genesis block.
                if block.block.previous.is_none() {
                    self.blocks.push(block)
                } else {
                    // its no genesis block
                }
            }
        }
    }
}
