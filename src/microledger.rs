use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::seal_bundle::SealBundle;
use crate::verifier::Verifier;
use crate::{
    block::{Block, SignedBlock},
    digital_fingerprint::DigitalFingerprint,
    Result,
};
use crate::{Encode, Identifier, Signature};

#[derive(Error, Debug)]
pub enum MicroledgerError {
    #[error("No block of given fingerprint: {0}")]
    MissingBlock(DigitalFingerprint),
    #[error("Block doesn't match")]
    WrongBlock,
    #[error("Signatures doesn't match controlling identifier")]
    WrongSigner,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct MicroLedger<S, V, I>
where
    S: Serialize + Signature<Identifier = I>,
    V: Verifier<Signature = S>,
    I: Identifier + Serialize,
{
    #[serde(rename = "bs")]
    pub blocks: Vec<SignedBlock<I, S>>,
    #[serde(skip)]
    pub verifier: Arc<V>,
}

impl<S, V, I> MicroLedger<S, V, I>
where
    S: Serialize + Clone + Signature<Identifier = I>,
    V: Verifier<Signature = S>,
    I: Identifier + Serialize + Clone + PartialEq,
{
    pub fn new(verifier: Arc<V>) -> Self {
        MicroLedger {
            blocks: vec![],
            verifier,
        }
    }

    pub fn append_block(&mut self, signed_block: SignedBlock<I, S>) -> Result<()> {
        self.blocks.append(&mut vec![signed_block]);
        Ok(())
    }

    pub fn pre_anchor_block(
        &self,
        controlling_identifiers: Vec<I>,
        seal_bundle: &SealBundle,
    ) -> Result<Block<I>> {
        let prev = self
            .blocks
            .last()
            .map(|sb| -> Result<_> { Ok(DigitalFingerprint::derive(&Encode::encode(&sb.block)?)) });

        let prev = match prev {
            Some(Ok(sp)) => Some(sp),
            Some(Err(e)) => return Err(e),
            None => None,
        };
        let seals = seal_bundle.get_fingerprints();
        Ok(Block::new(seals, prev, controlling_identifiers))
    }

    pub fn anchor(&mut self, block: SignedBlock<I, S>) -> Result<()> {
        let last = self.get_last_block();
        let controllers_check = match self.current_controlling_identifiers() {
            // Provided signatures creators should match controlling identifiers
            // designated in last block
            Some(controllers) => block
                .check_controlling_identifiers(&controllers)
                .then_some(true)
                .ok_or(MicroledgerError::WrongSigner)?,
            // It's first block, check controlling identifeir from itself
            None => block
                .check_controlling_identifiers(&block.block.controlling_identifiers)
                .then_some(true)
                .ok_or(MicroledgerError::WrongSigner)?,
        };
        // Checks block binding and signatures.
        if block.check_previous_block(last)?
            && block.verify(self.verifier.clone())?
            && controllers_check
        {
            self.append_block(block)
        } else {
            Err(MicroledgerError::WrongBlock.into())
        }
    }

    pub fn get_last_block(&self) -> Option<&Block<I>> {
        self.blocks.last().map(|last| &last.block)
    }

    /// Returns copy of sub-microledger which last block matches the given fingerprint.
    pub fn at(&self, block_id: &DigitalFingerprint) -> Option<Self> {
        let position = self
            .blocks
            .iter()
            .position(|b| Encode::encode(&b.block).map_or(false, |x| block_id.verify_binding(&x)));
        // .take_while(|b| !block_id.verify_binding(&Serialization::serialize(&b.block))).collect();
        if let Some(position) = position {
            let blocks: Vec<_> = self.blocks.clone().into_iter().take(position + 1).collect();
            Some(Self {
                blocks,
                verifier: self.verifier.clone(),
            })
        } else {
            None
        }
    }

    fn current_controlling_identifiers(&self) -> Option<Vec<I>> {
        self.get_last_block()
            .map(|block| block.controlling_identifiers.clone())
    }

    /// Returns block of given fingerprint
    pub fn get_block(&self, fingerprint: DigitalFingerprint) -> Result<Block<I>> {
        self.blocks
            .iter()
            .find(|b| Encode::encode(&b.block).map_or(false, |x| fingerprint.verify_binding(&x)))
            .map(|b| b.block.clone())
            .ok_or_else(|| MicroledgerError::MissingBlock(fingerprint.clone()).into())
    }

    pub fn get_block_by_fingerprint(
        &self,
        fingerprint: &DigitalFingerprint,
    ) -> Result<&SignedBlock<I, S>> {
        self.blocks
            .iter()
            .find(|b| Encode::encode(&b.block).map_or(false, |x| fingerprint.verify_binding(&x)))
            .ok_or_else(|| MicroledgerError::MissingBlock(fingerprint.clone()).into())
    }

    // pub fn get_seal_datums(&self, fingerprint: &DigitalFingerprint) -> Result<Vec<String>> {
    //     let block = self.get_block_by_fingerprint(fingerprint)?;
    //     let found_data: Result<Vec<_>> = block
    //         .block
    //         .seals
    //         .iter()
    //         .map(|s| match s {
    //             Seal::Attached(sai) => block
    //                 .attached_seal
    //                 .get(&sai.to_string())
    //                 .ok_or_else(|| Error::BlockError("Can't find attached data".into())),
    //         })
    //         .collect();
    //     found_data
    // }
}
