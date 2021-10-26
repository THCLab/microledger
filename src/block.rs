use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{
    controlling_identifier::ControllingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    error::Error,
    microledger::Result,
    seal_bundle::{BlockAttachment, SealBundle},
    seals::Seal,
    signature::Signature,
    Serialization,
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block {
    #[serde(rename = "s")]
    pub seals: Vec<Seal>,
    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub previous: Option<DigitalFingerprint>,
    #[serde(rename = "ci")]
    pub controlling_identifiers: Vec<ControllingIdentifier>,
}

impl Serialization for Block {
    fn serialize(&self) -> Vec<u8> {
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

    pub fn to_signed_block(
        self,
        signatures: Vec<Signature>,
        seal_bundle: &SealBundle,
    ) -> SignedBlock {
        let attachement = seal_bundle.get_attachement();
        SignedBlock {
            block: self,
            signatures,
            attached_seal: attachement,
        }
    }
}

impl Block {
    fn check_previous(&self, previous_block: Option<&Block>) -> Result<bool> {
        match self.previous {
            Some(ref prev) => match previous_block {
                Some(block) => Ok(prev.verify_binding(&Serialization::serialize(block))),
                None => Err(Error::BlockError("Incorect blocks binding".into())),
            },
            None => Ok(previous_block.is_none()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignedBlock {
    #[serde(rename = "bl")]
    pub block: Block,
    #[serde(rename = "si")]
    pub signatures: Vec<Signature>,
    // TODO should be vec in the future
    #[serde(rename = "at")]
    pub attached_seal: BlockAttachment,
}

// Checks if signed block matches the given block.
impl SignedBlock {
    pub fn verify(
        &self,
        controlling_identifiers: Option<Vec<ControllingIdentifier>>,
    ) -> Result<bool> {
        Ok(controlling_identifiers
            .unwrap_or_else(|| self.block.controlling_identifiers.clone())
            .iter()
            .all(|ci| {
                ci.check_signatures(&Serialization::serialize(&self.block), &self.signatures)
                    .unwrap()
            }))
    }

    pub fn check_block(&self, block: Option<&Block>) -> Result<bool> {
        Ok(self.block.check_previous(block)? && self.check_seals()?)
    }

    fn check_seals(&self) -> Result<bool> {
        // check if seal of given hash exists in block attachement
        if self
            .block
            .seals
            .iter()
            // TODO check all seals
            .filter(|s| matches!(s, Seal::Attached(_)))
            .all(|s| self.attached_seal.clone().get(&s.fingerprint()).is_some())
        {
            Ok(true)
        } else {
            Err(Error::BlockError(
                "anchored data doesn't exist in seal provider".into(),
            ))
        }
    }
}

#[cfg(test)]
pub mod test {
    use keri::{derivation::basic::Basic, keys::PublicKey};
    use rand::rngs::OsRng;
    use said::derivation::SelfAddressing;

    use crate::{
        block::Block, controlling_identifier::ControllingIdentifier,
        digital_fingerprint::DigitalFingerprint, seals::Seal, Serialization,
    };

    #[test]
    fn test_block_serialization() {
        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, _sk) = (kp.public, kp.secret);
        let bp = ControllingIdentifier::Basic(
            Basic::Ed25519.derive(PublicKey::new(pk.as_bytes().to_vec())),
        );

        let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev = Some(DigitalFingerprint::SelfAddressing(
            SelfAddressing::Blake3_256.derive("exmaple".as_bytes()),
        ));
        let block = Block::new(vec![Seal::Attached(seal)], prev, vec![(bp)]);
        println!("{}", String::from_utf8(block.serialize()).unwrap());

        let deserialized_block: Block = serde_json::from_slice(&block.serialize()).unwrap();
        assert_eq!(block.serialize(), deserialized_block.serialize());
    }
}
