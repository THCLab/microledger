use serde::Serialize;

use crate::{
    block::SignedBlock, controling_identifiers::ControlingIdentifier,
    digital_fingerprint::DigitalFingerprint, seal_provider::SealProvider, seals::Seal,
    signature::Signature,
};

pub struct MicroLedger<I, D, C, P, S>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize,
    P: SealProvider + Serialize,
    S: Signature + Serialize,
{
    blocks: Vec<SignedBlock<I, C, D, S, P>>,
    seal_list: Vec<I>,
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
        MicroLedger {
            blocks: vec![],
            seal_list: vec![],
        }
    }

    pub fn append(&mut self, block: SignedBlock<I, C, D, S, P>) {
        if self.blocks.last().unwrap().block.append(&block) {
            self.seal_list.push(block.block.seals.clone());
            self.blocks.push(block);
        } else {
            // wrong block
        }
    }
}
