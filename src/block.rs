use serde::{Deserialize, Serialize};

use crate::{
    controling_identifiers::ControlingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    error::Error,
    microledger::Result,
    seal_provider::{SealProvider, SealsAttachement},
    seals::Seal,
    signature::Signature,
    Serialization,
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block<I, D, C>
where
    I: Seal,
    D: DigitalFingerprint,
    C: ControlingIdentifier + Clone,
{
    #[serde(rename = "s")]
    pub seals: Vec<I>,
    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub previous: Option<D>,
    #[serde(rename = "ci")]
    pub controlling_identifiers: Vec<C>,
    #[serde(skip_serializing)]
    attachements: Option<SealsAttachement>,
}

impl<I, D, C> Serialization for Block<I, D, C>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
{
    fn serialize(&self) -> Vec<u8> {
        serde_json::to_string(self).unwrap().as_bytes().to_vec()
    }
}

impl<I, D, C> Block<I, D, C>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
{
    pub fn new(seals: Vec<I>, previous: Option<D>, controlling_identifiers: Vec<C>) -> Self {
        Self {
            seals,
            previous,
            controlling_identifiers,
            attachements: None,
        }
    }

    pub fn attach(&mut self, data: &[u8]) -> Result<()> {
        let mut attachements = self.attachements.clone().unwrap_or_default();
        let seal: I = attachements.save(data).unwrap();
        self.seals.push(seal);
        self.attachements = Some(attachements);

        Ok(())
    }

    pub fn to_signed_block<S: Signature + Serialize>(
        self,
        signatures: Vec<S>,
        // attachements: P,
    ) -> SignedBlock<I, C, D, S, SealsAttachement> {
        // TODO remove expect
        let attachement = self.attachements.clone().expect("Empty seal provider");
        SignedBlock {
            block: self,
            signatures,
            attached_seal: attachement,
        }
    }
}

impl<I, D, C> Block<I, D, C>
where
    I: Seal + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
{
    fn check_previous(&self, previous_block: Option<&Block<I, D, C>>) -> Result<bool> {
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
pub struct SignedBlock<I, C, D, S, P>
where
    I: Seal + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    S: Signature + Serialize,
    P: SealProvider + Clone,
{
    #[serde(rename = "bl")]
    pub block: Block<I, D, C>,
    #[serde(rename = "si")]
    pub signatures: Vec<S>,
    // TODO should be vec in the future
    #[serde(rename = "at")]
    pub attached_seal: P,
}

// Checks if signed block matches the given block.
impl<I, C, D, S, P> SignedBlock<I, C, D, S, P>
where
    I: Seal + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    S: Signature + Serialize,
    P: SealProvider + Clone,
    S: Signature,
{
    pub fn verify(&self, controlling_identifiers: Option<Vec<C>>) -> Result<bool> {
        Ok(controlling_identifiers
            .unwrap_or_else(|| self.block.controlling_identifiers.clone())
            .iter()
            .all(|ci| {
                ci.check_signatures(&Serialization::serialize(&self.block), &self.signatures)
                    .unwrap()
            }))
    }

    pub fn check_block(&self, block: Option<&Block<I, D, C>>) -> Result<bool> {
        Ok(self.check_seals()? && self.block.check_previous(block)?)
    }

    fn check_seals(&self) -> Result<bool> {
        // check if seal of given hash exists in provider
        if self
            .block
            .seals
            .iter()
            .all(|s| self.attached_seal.clone().check(s))
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
    use keri::{derivation::basic::Basic, keys::PublicKey, prefix::BasicPrefix};
    use rand::rngs::OsRng;
    use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

    use crate::{block::Block, seals::AttachmentSeal, Serialization};
    #[test]
    fn test_block_serialization() {
        type BlockExample = Block<AttachmentSeal, SelfAddressingPrefix, BasicPrefix>;
        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, _sk) = (kp.public, kp.secret);
        let bp = Basic::Ed25519.derive(PublicKey::new(pk.as_bytes().to_vec()));

        let seal = AttachmentSeal::new("example".as_bytes()); // SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev: Option<SelfAddressingPrefix> =
            Some(SelfAddressing::Blake3_256.derive("exmaple".as_bytes()));
        let block: BlockExample = Block::new(vec![seal], prev, vec![bp]);
        println!("{}", String::from_utf8(block.serialize()).unwrap());

        let deserialized_block: BlockExample = serde_json::from_slice(&block.serialize()).unwrap();
        assert_eq!(block.serialize(), deserialized_block.serialize());
    }
}
