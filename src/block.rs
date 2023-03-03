use std::{fmt::Debug, sync::Arc};

use cesrox::{parse, payload::Payload, ParsedData};
use serde::{Deserialize, Serialize};

use crate::{
    controlling_identifier::ControllingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    error::Error,
    seals::Seal,
    signature::{KeriSignature, KeriSignatures, ToCesr},
    verifier::Verifier,
    Encode,
};
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block {
    #[serde(rename = "s")]
    pub seals: Vec<Seal>,
    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub previous: Option<DigitalFingerprint>,
    #[serde(rename = "ci")]
    pub controlling_identifiers: Vec<ControllingIdentifier>,
}

impl Encode for Block {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_string(self).unwrap().as_bytes().to_vec()
    }
}

impl Block {
    pub fn new(
        seals: Vec<Seal>,
        previous: Option<DigitalFingerprint>,
        controlling_identifiers: Vec<ControllingIdentifier>,
    ) -> Self {
        Self {
            seals,
            previous,
            controlling_identifiers,
        }
    }

    pub fn to_signed_block<S>(self, signatures: Vec<S>) -> SignedBlock<S> {
        SignedBlock {
            block: self,
            signatures,
        }
    }
}

impl Block {
    fn check_previous(&self, previous_block: Option<&Block>) -> Result<bool> {
        match self.previous {
            Some(ref prev) => match previous_block {
                Some(block) => Ok(prev.verify_binding(&Encode::encode(block))),
                None => Err(Error::BlockError("Incorect blocks binding".into())),
            },
            None => Ok(previous_block.is_none()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedBlock<S> {
    pub block: Block,
    pub signatures: Vec<S>,
}

// Checks if signed block matches the given block.
impl<S: Clone> SignedBlock<S> {
    pub fn new(block: Block, sigs: Vec<S>) -> Self {
        Self {
            block,
            signatures: sigs,
        }
    }
    pub fn verify<V: Verifier<Signature = S>>(
        &self,
        verifier: Arc<V>,
        controlling_identifiers: Option<Vec<ControllingIdentifier>>,
    ) -> Result<bool> {
        // TODO
        // Check controlling identifiers
        verifier.verify(&Encode::encode(&self.block), self.signatures.clone())
    }

    pub fn check_block(&self, block: Option<&Block>) -> Result<bool> {
        Ok(self.block.check_previous(block)?) // && self.check_seals()?)
    }
}
impl SignedBlock<KeriSignature> {
    pub fn to_cesr(&self) -> Result<Vec<u8>> {
        let payload = Payload::JSON(Encode::encode(&self.block));
        let att: Vec<cesrox::group::Group> = self
            .signatures
            .iter()
            .map(|a| a.to_cesr_attachment())
            .collect::<Result<_>>()
            .unwrap();
        let d = ParsedData {
            payload,
            attachments: att,
        };
        Ok(d.to_cesr().unwrap())
    }

    pub fn from_cesr(stream: &[u8]) -> Result<Self> {
        let (_rest, parsed) = parse(stream).unwrap();
        Ok(parsed.into())
    }
}

impl From<ParsedData> for SignedBlock<KeriSignature> {
    fn from(parsed: ParsedData) -> Self {
        let block: Block = match parsed.payload {
            Payload::JSON(json) => serde_json::from_slice(&json).unwrap(),
            Payload::CBOR(_) => todo!(),
            Payload::MGPK(_) => todo!(),
        };
        let signatures: Vec<_> = parsed
            .attachments
            .into_iter()
            .map(|g| {
                let s: KeriSignatures = g.into();
                s.0
            })
            .flatten()
            .collect();
        block.to_signed_block(signatures)
    }
}

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use cesrox::primitives::codes::self_signing::SelfSigning;
    use ed25519_dalek::ExpandedSecretKey;
    use keri::{
        database::SledEventDatabase,
        keys::PublicKey,
        prefix::{BasicPrefix, SelfSigningPrefix},
        processor::{basic_processor::BasicProcessor, validator::EventValidator},
    };
    use rand::rngs::OsRng;
    use sai::derivation::SelfAddressing;
    use tempfile::Builder;

    use crate::{
        block::{Block, SignedBlock},
        controlling_identifier::ControllingIdentifier,
        digital_fingerprint::DigitalFingerprint,
        seals::Seal,
        signature::KeriSignature,
        Encode,
    };

    #[test]
    fn test_block_serialization() {
        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, _sk) = (kp.public, kp.secret);
        let bp = ControllingIdentifier::Keri(keri::prefix::IdentifierPrefix::Basic(
            BasicPrefix::Ed25519(PublicKey::new(pk.as_bytes().to_vec())),
        ));

        let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev = Some(DigitalFingerprint::SelfAddressing(
            SelfAddressing::Blake3_256.derive("exmaple".as_bytes()),
        ));
        let block = Block::new(vec![Seal::Attached(seal)], prev, vec![(bp)]);
        println!("{}", String::from_utf8(block.encode()).unwrap());

        let deserialized_block: Block = serde_json::from_slice(&block.encode()).unwrap();
        assert_eq!(block.encode(), deserialized_block.encode());
    }
}
