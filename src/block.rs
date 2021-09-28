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
            previous: previous,
            rules,
            seal_provider,
        }
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
    pub block: Block<I, D, C, P>,
    pub signatures: Vec<S>,
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
                        // anchored data doesn't exist in seal provider
                        false
                    }
                } else {
                    // previous block doesn't match
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
            false
        };
        todo!()
    }
}
