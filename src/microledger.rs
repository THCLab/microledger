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

// #[cfg(test)]
// pub mod test {
//     use keri::prefix::SelfSigningPrefix;
//     use said::prefix::SelfAddressingPrefix;

//     use crate::{
//         controling_identifiers::Rules, microledger::MicroLedger, seal_provider::SealsAttachement,
//         seals::AttachmentSeal,
//     };

//     #[test]
//     fn test_microledger_deserialization() {
//         type MicroledgerExample = MicroLedger<
//             AttachmentSeal,
//             SelfAddressingPrefix,
//             Rules,
//             SelfSigningPrefix,
//             SealsAttachement,
//         >;

//         let serialized_microledger = r#"{"blocks":[{"bl":{"seals":["ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4"],"previous":null,"rules":{"public_keys":["DNMchIYJM4PJim29UD5FMNtoKmWNFd6MX0Y2yXj2sfPY"]}},"si":["0Bypyj6RJaj-TkFD0hy4894ijV9ECxFhxWijqY1lB1Eya_Cp-Au1903ZN8f6BA98FuHW7tJNsMI_ihb5vgTFj-Aw"],"at":{"seals":{"ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4":"some message"}}},{"bl":{"seals":["EkmxFLOdaFuSibYsu6lSmab8RnIUKxjYoI6dzVawLx6g"],"previous":"EvcWUIdjA2xqEGNzf4NMNgZSPNS-C1x80aae20t_EdK0","rules":{"public_keys":["Dp-HXh0oSCldjgbYO29hYrd0R2BJYjgwrNxsJRY_ABPs"]}},"si":["0B83IzQY_CS2jdzC3Ymj3u6PO0vTmk34r4aYzIELUr5B0XAT_Z2qlkVFn0WYYGqLY6xsPl9xl1GQwGEtosx1JNBA"],"at":{"seals":{"EkmxFLOdaFuSibYsu6lSmab8RnIUKxjYoI6dzVawLx6g":"another message"}}}]}"#;
//         let deserialize_microledger: MicroledgerExample =
//             serde_json::from_str(&serialized_microledger).unwrap();
//         assert_eq!(2, deserialize_microledger.blocks.len());
//     }
// }
