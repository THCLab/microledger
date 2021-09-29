use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    controling_identifiers::ControlingIdentifier, digital_fingerprint::DigitalFingerprint,
    seal_provider::SealProvider, seals::Seal, signature::Signature, Serialization,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Block<I, D, C, P>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize,
    P: SealProvider + Serialize,
{
    pub seals: I,
    pub previous: Option<D>,
    pub rules: C,
    pub seal_provider: P,
}

impl<I, D, C, P> Serialization for Block<I, D, C, P>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize,
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
    C: ControlingIdentifier + Serialize,
    P: SealProvider + Serialize,
{
    pub fn new(seal: I, previous: Option<D>, rules: C, seal_provider: P) -> Self {
        Self {
            seals: seal,
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
    C: ControlingIdentifier + Serialize,
    D: DigitalFingerprint + Serialize,
    P: SealProvider + Serialize,
{
    fn check_block(&self, block: &Block<I, D, C, P>) -> bool {
        match &block.previous {
            Some(prev) => {
                // check if previous event matches
                if prev.verify_binding(&Serialization::serialize(self)) {
                    // check if seal of given hash exists
                    if block.seal_provider.check(&self.seals) {
                        // ok, block can be added
                        true
                    } else {
                        println!("anchored data doesn't exist in seal provider");
                        false
                    }
                } else {
                    println!("previous block doesn't match");
                    false
                }
            }
            None => {
                // it's initial block
                todo!()
            }
        }
    }

    pub fn append<S: Signature + Serialize>(&self, block: &SignedBlock<I, C, D, S, P>) -> bool {
        if self
            .rules
            .check_signatures(&Serialization::serialize(&block.block), &block.signatures)
        {
            self.check_block(&block.block)
        } else {
            // signatures doesn't match the rules
            println!("signatures doesnt match the rules");
            false
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
    C: ControlingIdentifier + Serialize,
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

#[cfg(test)]
pub mod test {
    use keri::{prefix::SelfSigningPrefix, signer::CryptoBox};
    use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

    use crate::{
        block::Block, controling_identifiers::Rules, seal_provider::DummyProvider, Serialization,
    };
    #[test]
    fn test_block_serialization() {
        let pk = CryptoBox::new().unwrap().next_pub_key.key(); // .public_key().key();
        let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev: Option<SelfAddressingPrefix> =
            Some(SelfAddressing::Blake3_256.derive("exmaple".as_bytes()));
        let rules = Rules::new(vec![pk]);
        let provider = DummyProvider::new();
        let block = Block::new(seal, prev, rules, provider);
        println!("{}", String::from_utf8(block.serialize()).unwrap());

        let des: Block<SelfAddressingPrefix, SelfAddressingPrefix, Rules, DummyProvider> =
            serde_json::from_slice(&block.serialize()).unwrap();
        assert_eq!(block.serialize(), des.serialize());

        let signed_block = block.to_signed_block::<SelfSigningPrefix>(
            vec![],
            &vec![("dsds".to_string(), "fff".to_string())],
        );
        println!(
            "signed: \n{}",
            serde_json::to_string(&signed_block).unwrap()
        )
    }
}
