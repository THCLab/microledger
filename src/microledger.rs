use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::Serialization;
use crate::{
    block::{Block, SignedBlock},
    controling_identifiers::ControlingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    seal_provider::SealProvider,
    seals::Seal,
    signature::Signature,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize)]
pub struct MicroLedger<I, D, C, S, P>
where
    I: Seal + Serialize,
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    S: Signature + Serialize,
    P: SealProvider + Serialize + Clone,
{
    pub blocks: Vec<SignedBlock<I, C, D, S, P>>,
}

impl<I, D, C, S, P> MicroLedger<I, D, C, S, P>
where
    I: Seal + Serialize + Clone,
    D: DigitalFingerprint + Serialize + Clone,
    C: ControlingIdentifier + Serialize + Clone,
    S: Signature + Serialize + Clone,
    P: SealProvider + Serialize + Clone,
{
    pub fn new() -> Self {
        MicroLedger { blocks: vec![] }
    }

    pub fn pre_anchor_block(&self, attachements: Vec<I>, rules: C) -> Block<I, D, C>
    where
        I: Seal + Serialize + Clone,
        D: DigitalFingerprint + Serialize,
        C: ControlingIdentifier + Serialize + Clone,
        S: Signature + Serialize,
    {
        let prev = self
            .blocks
            .last()
            .map(|sb| D::derive(&Serialization::serialize(&sb.block)));

        Block::new(attachements, prev, rules)
    }

    fn get_last_block(&self) -> Option<&Block<I, D, C>> {
        self.blocks.last().map(|last| &last.block)
    }

    fn at(&self, block_id: D) -> Option<Self> {
        let position = self
            .blocks
            .clone()
            .iter()
            .position(|b| block_id.verify_binding(&Serialization::serialize(&b.block)));
        // .take_while(|b| !block_id.verify_binding(&Serialization::serialize(&b.block))).collect();
        let blocks: Vec<_> = self
            .blocks
            .clone()
            .into_iter()
            .take(position.unwrap() + 1)
            .collect();
        Some(Self { blocks })
    }

    fn current_rules(&self) -> Result<Option<C>> {
        Ok(self.get_last_block().map(|block| block.rules.clone()))
    }

    pub fn anchor(&self, block: SignedBlock<I, C, D, S, P>) -> Result<Self> {
        let last = self.get_last_block();
        // Checks block binding and signatures.
        if block.check_block(last)? && block.verify(self.current_rules()?)? {
            let mut blocks = self.blocks.clone();
            blocks.push(block);
            Ok(MicroLedger {
                blocks: blocks.to_vec(),
            })
        } else {
            Err(Error::MicroError("Wrong block".into()))
        }
    }
}

#[cfg(test)]
pub mod test {
    use keri::prefix::SelfSigningPrefix;
    use said::prefix::SelfAddressingPrefix;

    use crate::{
        controling_identifiers::Rules, microledger::MicroLedger, seal_provider::SealsAttachement,
        seals::AttachmentSeal, Serialization,
    };

    #[test]
    fn test_microledger_traversing() {
        type MicroledgerExample = MicroLedger<
            AttachmentSeal,
            SelfAddressingPrefix,
            Rules,
            SelfSigningPrefix,
            SealsAttachement,
        >;

        let serialized_microledger = r#"{"blocks":[{"bl":{"seals":["ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4"],"previous":null,"rules":{"public_keys":["Dxd_pOfWnt5vqsj-VLym6wuHxxex9Z4wazIZMXyVbZBY"]}},"si":["0BGCml-d3bm6WlgRFE3_gND3556YgZsZsuh5OfSH5qge95G8R0zxSVjuCAygVa-Ta2VZrA4lZ7pNTDz5vozE3oDw"],"at":{"seals":{"ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4":"some message"}}},{"bl":{"seals":["E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I"],"previous":"EgFkVDi4saiPwwCfuxw6XlFafQ4RKdPSoC_hLSgygq24","rules":{"public_keys":["DRvBjYO4-wuK7mCpntD4Su7yBNqP3W30YUAiV1aQffyo"]}},"si":["0BWbx_bPAMLcw85l5Ksv3llp8h5vtIdDC7r2umwkKxV5McqJk2XHqKTaYNlfRchkIr4KozWGz8LVLw4AzD4EHdDQ"],"at":{"seals":{"E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I":"one more message"}}},{"bl":{"seals":["E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I"],"previous":"E8Kfq3CHZe0gL6wUBQ9JJ7FOGBchDgAd_DkiHBTbO2CQ","rules":{"public_keys":["DRvBjYO4-wuK7mCpntD4Su7yBNqP3W30YUAiV1aQffyo"]}},"si":["0BUmW5US8JPox7b-yaKPuc5xxS_ouy63lyfFc2fgBwyLWYpKSvO7KUJUirqfgefUx8igqLJANKcsJQmTvBdwfGAw"],"at":{"seals":{"E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I":"one more message"}}}]}"#;
        let deserialize_microledger: MicroledgerExample =
            serde_json::from_str(&serialized_microledger).unwrap();
        assert_eq!(3, deserialize_microledger.blocks.len());

        let second_block_id: SelfAddressingPrefix = "E8Kfq3CHZe0gL6wUBQ9JJ7FOGBchDgAd_DkiHBTbO2CQ"
            .parse()
            .unwrap();

        // test `at` function
        let at_micro = deserialize_microledger.at(second_block_id).unwrap();
        assert_eq!(at_micro.blocks.len(), 2);

        // test `get_last_block`
        let last = deserialize_microledger.get_last_block();
        let sed_last = r#"{"seals":["E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I"],"previous":"E8Kfq3CHZe0gL6wUBQ9JJ7FOGBchDgAd_DkiHBTbO2CQ","rules":{"public_keys":["DRvBjYO4-wuK7mCpntD4Su7yBNqP3W30YUAiV1aQffyo"]}}"#;
        assert_eq!(serde_json::to_string(&last.unwrap()).unwrap(), sed_last);

        assert_ne!(
            last.unwrap().serialize(),
            at_micro.get_last_block().unwrap().serialize()
        );
    }
}
