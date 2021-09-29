use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    controling_identifiers::ControlingIdentifier, digital_fingerprint::DigitalFingerprint,
    error::Error, microledger::Result, seal_provider::SealProvider, seals::Seal,
    signature::Signature, Serialization,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Block<I, D, C, P>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    P: SealProvider + Serialize,
{
    pub seals: Vec<I>,
    pub previous: Option<D>,
    pub rules: C,
    pub seal_provider: P,
}

impl<I, D, C, P> Serialization for Block<I, D, C, P>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    P: SealProvider + Serialize,
{
    fn serialize(&self) -> Vec<u8> {
        serde_json::to_string(self).unwrap().as_bytes().to_vec()
    }
}

impl<I, D, C, P> Block<I, D, C, P>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    P: SealProvider + Serialize,
{
    pub fn new(seals: Vec<I>, previous: Option<D>, rules: C, seal_provider: P) -> Self {
        Self {
            seals,
            previous,
            rules,
            seal_provider,
        }
    }

    pub fn to_signed_block<S: Signature + Serialize>(
        self,
        signatures: Vec<S>,
        attachements: &[(String, String)],
    ) -> SignedBlock<I, C, D, S, P> {
        let mut attachements_dict = HashMap::new();
        if !attachements.is_empty() {
            attachements.iter().for_each(|(k, v)| {
                attachements_dict.insert(k.to_string(), v.to_string());
            });
        };

        SignedBlock {
            block: self,
            signatures,
            attached_seal: attachements_dict,
        }
    }
}

impl<I, D, C, P> Block<I, D, C, P>
where
    I: Seal + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    P: SealProvider + Serialize,
{
    fn check_seals(&self) -> Result<bool> {
        // check if seal of given hash exists in provider
        if self.seals.iter().all(|s| self.seal_provider.check(s)) {
            Ok(true)
        } else {
            Err(Error::BlockError(
                "anchored data doesn't exist in seal provider".into(),
            ))
        }
    }

    fn check_previous(&self, previous_block: Option<&Block<I, D, C, P>>) -> Result<bool> {
        match self.previous {
            Some(ref prev) => match previous_block {
                Some(block) => Ok(prev.verify_binding(&Serialization::serialize(block))),
                None => Err(Error::BlockError("Incorect blocks binding".into())),
            },
            None => Ok(previous_block.is_none()),
        }
    }
}

// Dictionary with hash of data as a key and data as value.
pub type Attachement = HashMap<String, String>;

impl SealProvider for Attachement {
    fn check<S: Seal>(&self, s: &S) -> bool {
        self.get(&s.to_str()).is_some()
    }

    fn get<S: Seal>(&self, s: &S) -> Option<String> {
        self.get(&s.to_str()).map(|s| s.to_owned())
    }
}

#[derive(Clone, Serialize)]
pub struct SignedBlock<I, C, D, S, P>
where
    I: Seal + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    S: Signature + Serialize,
    P: SealProvider + Serialize,
{
    #[serde(rename = "bl")]
    pub block: Block<I, D, C, P>,
    #[serde(rename = "si")]
    pub signatures: Vec<S>,
    #[serde(rename = "at")]
    pub attached_seal: Attachement,
}

// Checks if signed block matches the given block.
impl<I, C, D, S, P> SignedBlock<I, C, D, S, P>
where
    I: Seal + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    D: DigitalFingerprint + Serialize,
    S: Signature + Serialize,
    P: SealProvider + Serialize,
    S: Signature,
{
    pub fn verify(&self, rules: Option<C>) -> Result<bool> {
        rules
            .unwrap_or(self.block.rules.clone())
            .check_signatures(&Serialization::serialize(&self.block), &self.signatures)
    }

    pub fn check_block(&self, block: Option<&Block<I, D, C, P>>) -> Result<bool> {
        Ok(self.block.check_seals()? && self.block.check_previous(block)?)
    }
}

#[cfg(test)]
pub mod test {
    use rand::rngs::OsRng;
    use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

    use crate::{
        block::Block, controling_identifiers::Rules, seal_provider::DummyProvider, Serialization,
    };
    #[test]
    fn test_block_serialization() {
        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, _sk) = (kp.public.to_bytes().to_vec(), kp.secret);

        let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev: Option<SelfAddressingPrefix> =
            Some(SelfAddressing::Blake3_256.derive("exmaple".as_bytes()));
        let rules = Rules::new(vec![pk]);
        let provider = DummyProvider::default();
        let block = Block::new(vec![seal], prev, rules, provider);
        println!("{}", String::from_utf8(block.serialize()).unwrap());

        let deserialized_block: Block<
            SelfAddressingPrefix,
            SelfAddressingPrefix,
            Rules,
            DummyProvider,
        > = serde_json::from_slice(&block.serialize()).unwrap();
        assert_eq!(block.serialize(), deserialized_block.serialize());
    }
}
