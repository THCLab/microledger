use std::{fmt::Debug, sync::Arc};

use said::derivation::HashFunctionCode;
use said::sad::sad_macros::SAD;
use said::sad::{SerializationFormats, SAD};
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{error::Error, seals::Seal, verifier::Verifier, Encode, Identifier};
use crate::{Result, Signature};

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Incorect previous block binding")]
    WrongBlockBinding,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, SAD)]
pub struct Block<I: Identifier + Serialize + Clone> {
    #[serde(rename = "ci")]
    pub controlling_identifiers: Vec<I>,
    #[serde(rename = "d")]
    #[said]
    pub digital_fingerprint: Option<SelfAddressingIdentifier>,
    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub previous: Option<SelfAddressingIdentifier>,
    #[serde(rename = "s")]
    pub seals: Vec<Seal>,
}

impl<I: Identifier + Serialize + Clone> Encode for Block<I> {
    fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_string(self)
            .map(|encoded| encoded.as_bytes().to_vec())
            .map_err(Error::EncodeError)
    }
}

impl<I: Identifier + Serialize + Clone> Block<I> {
    pub fn new(
        seals: Vec<Seal>,
        previous: Option<SelfAddressingIdentifier>,
        controlling_identifiers: Vec<I>,
    ) -> Self {
        let new_block = Self {
            digital_fingerprint: None,
            seals,
            previous,
            controlling_identifiers,
        };
        new_block.compute_digest(HashFunctionCode::Blake3_256, SerializationFormats::JSON)
    }

    pub fn get_fingerprint(&self) -> Result<SelfAddressingIdentifier> {
        self.digital_fingerprint
            .clone()
            .ok_or(Error::MissingFingerprintError)
    }

    pub fn to_signed_block<S: Signature<Identifier = I>>(
        self,
        signatures: Vec<S>,
    ) -> SignedBlock<I, S> {
        SignedBlock {
            block: self,
            signatures,
        }
    }
}

impl<I: Identifier + Serialize + Clone> Block<I> {
    fn check_previous(&self, previous_block: Option<&Block<I>>) -> Result<bool> {
        match self.previous {
            Some(ref prev) => match previous_block {
                Some(block) => Ok(prev.eq(block
                    .digital_fingerprint
                    .as_ref()
                    .ok_or(Error::MissingFingerprintError)?)),
                None => Err(BlockError::WrongBlockBinding.into()),
            },
            None => Ok(previous_block.is_none()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedBlock<I, S>
where
    I: Identifier + Serialize + Clone,
    S: Signature<Identifier = I>,
{
    pub block: Block<I>,
    pub signatures: Vec<S>,
}

// Checks if signed block matches the given block.
impl<S, I> SignedBlock<I, S>
where
    S: Clone + Signature<Identifier = I>,
    I: Identifier + Serialize + PartialEq + Clone,
{
    pub fn new(block: Block<I>, sigs: Vec<S>) -> Self {
        Self {
            block,
            signatures: sigs,
        }
    }
    pub fn verify<V: Verifier<Signature = S>>(&self, verifier: Arc<V>) -> Result<bool> {
        verifier.verify(&Encode::encode(&self.block)?, self.signatures.clone())
    }

    pub fn check_controlling_identifiers(&self, controlling_identifiers: &[I]) -> bool {
        self.signatures
            .iter()
            .filter_map(|signature| signature.get_signer())
            .all(|signer| controlling_identifiers.contains(&signer))
    }

    pub fn check_previous_block(&self, block: Option<&Block<I>>) -> Result<bool> {
        self.block.check_previous(block) // && self.check_seals()?)
    }
}
