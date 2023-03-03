use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Encode;
use crate::error::Error;
use crate::seal_bundle::SealBundle;
use crate::signature::{Verify, KeriSignature};
use crate::verifier::Verifier;
use crate::{
    block::{Block, SignedBlock},
    controlling_identifier::ControllingIdentifier,
    digital_fingerprint::DigitalFingerprint,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct MicroLedger<S: Verify + Serialize, V: Verifier<Signature = S>> {
    #[serde(rename = "bs")]
    pub blocks: Vec<SignedBlock<S>>,
    #[serde(skip)]
    pub verifier: Arc<V>,
}

impl<S: Verify + Serialize +  Clone, V: Verifier<Signature = S>> MicroLedger<S, V> {
    pub fn new(verifier: Arc<V>) -> Self {
        MicroLedger { blocks: vec![], verifier }
    }

    pub fn append_block(&mut self, signed_block: SignedBlock<S>) -> Result<()> {
        self.blocks.append(&mut vec![signed_block]);
        Ok(())
    }

    pub fn pre_anchor_block(
        &self,
        controlling_identifiers: Vec<ControllingIdentifier>,
        seal_bundle: &SealBundle,
    ) -> Block {
        let prev = self
            .blocks
            .last()
            .map(|sb| DigitalFingerprint::derive(&Encode::encode(&sb.block)));

        let seals = seal_bundle.get_fingerprints();
        Block::new(seals, prev, controlling_identifiers)
    }

    pub fn anchor(&mut self, block: SignedBlock<S>) -> Result<()> {
        let last = self.get_last_block();
        // Checks block binding and signatures.
        if block.check_block(last)? && block.verify(self.verifier.clone(), self.current_controlling_identifiers()?)? {
            self.append_block(block)
        } else {
            Err(Error::MicroError("Wrong block".into()))
        }
    }

    pub fn get_last_block(&self) -> Option<&Block> {
        self.blocks.last().map(|last| &last.block)
    }

    /// Returns copy of sub-microledger which last block matches the given fingerprint.
    pub fn at(&self, block_id: &DigitalFingerprint) -> Option<Self> {
        let position = self
            .blocks
            .iter()
            .position(|b| block_id.verify_binding(&Encode::encode(&b.block)));
        // .take_while(|b| !block_id.verify_binding(&Serialization::serialize(&b.block))).collect();
        let blocks: Vec<_> = self
            .blocks
            .clone()
            .into_iter()
            .take(position.unwrap() + 1)
            .collect();
        Some(Self { blocks, verifier: self.verifier.clone() })
    }

    fn current_controlling_identifiers(&self) -> Result<Option<Vec<ControllingIdentifier>>> {
        Ok(self
            .get_last_block()
            .map(|block| block.controlling_identifiers.clone()))
    }

    /// Returns block of given fingerprint
    pub fn get_block(&self, fingerprint: DigitalFingerprint) -> Result<Block> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Encode::encode(&b.block)))
            .map(|b| b.block.clone())
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    fn get_block_by_fingerprint(&self, fingerprint: &DigitalFingerprint) -> Result<&SignedBlock<S>> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Encode::encode(&b.block)))
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
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
impl<V: Verifier<Signature = KeriSignature>> MicroLedger<KeriSignature, V> {
    pub fn new_from_cesr(stream: &[u8], verifier: Arc<V>) -> Result<Self> {
        let (_rest, parsed_stream) = cesrox::parse_many(stream).unwrap();
        let mut microledger = MicroLedger::new(verifier);
        parsed_stream.into_iter().for_each(|pd| microledger.append_block(pd.into()).unwrap());
        Ok(microledger)
    }

    pub fn to_cesr(&self) -> Result<Vec<u8>> {
        Ok(self.blocks
            .iter()
            .map(|bl| bl.to_cesr().unwrap())
            .flatten()
            .collect())
    }
}

