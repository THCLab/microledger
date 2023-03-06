use std::{fmt::Debug, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::{
    digital_fingerprint::DigitalFingerprint, error::Error, seals::Seal, verifier::Verifier, Encode,
    Identifier,
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block<I: Identifier + Serialize> {
    #[serde(rename = "s")]
    pub seals: Vec<Seal>,
    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub previous: Option<DigitalFingerprint>,
    #[serde(rename = "ci")]
    pub controlling_identifiers: Vec<I>,
}

impl<I: Identifier + Serialize> Encode for Block<I> {
    fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_string(self)
            .map(|encoded| encoded.as_bytes().to_vec())
            .map_err(Error::EncodeError)
    }
}

impl<I: Identifier + Serialize> Block<I> {
    pub fn new(
        seals: Vec<Seal>,
        previous: Option<DigitalFingerprint>,
        controlling_identifiers: Vec<I>,
    ) -> Self {
        Self {
            seals,
            previous,
            controlling_identifiers,
        }
    }

    pub fn to_signed_block<S>(self, signatures: Vec<S>) -> SignedBlock<I, S> {
        SignedBlock {
            block: self,
            signatures,
        }
    }
}

impl<I: Identifier + Serialize> Block<I> {
    fn check_previous(&self, previous_block: Option<&Block<I>>) -> Result<bool> {
        match self.previous {
            Some(ref prev) => match previous_block {
                Some(block) => Ok(prev.verify_binding(&Encode::encode(block)?)),
                None => Err(Error::BlockError("Incorect blocks binding".into())),
            },
            None => Ok(previous_block.is_none()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedBlock<I: Identifier + Serialize, S> {
    pub block: Block<I>,
    pub signatures: Vec<S>,
}

// Checks if signed block matches the given block.
impl<S: Clone, I: Identifier + Serialize> SignedBlock<I, S> {
    pub fn new(block: Block<I>, sigs: Vec<S>) -> Self {
        Self {
            block,
            signatures: sigs,
        }
    }
    pub fn verify<V: Verifier<Signature = S>>(
        &self,
        verifier: Arc<V>,
        _controlling_identifiers: Option<Vec<I>>,
    ) -> Result<bool> {
        // TODO
        // Check controlling identifiers
        verifier.verify(&Encode::encode(&self.block)?, self.signatures.clone())
    }

    pub fn check_block(&self, block: Option<&Block<I>>) -> Result<bool> {
        self.block.check_previous(block) // && self.check_seals()?)
    }
}
