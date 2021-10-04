use said::prefix::SelfAddressingPrefix;
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
    #[serde(rename = "bs")]
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

    pub fn pre_anchor_block(
        &self,
        attachements: Vec<I>,
        controlling_identifiers: Vec<C>,
    ) -> Block<I, D, C>
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

        let mut block = Block::new(vec![], prev, controlling_identifiers);
        attachements.iter().for_each(|at| {
            if let Some(data) = at.get_attachement() {
                block.attach(data.as_bytes()).unwrap();
            }
        });
        block
    }

    pub fn anchor(&self, block: SignedBlock<I, C, D, S, P>) -> Result<Self> {
        let last = self.get_last_block();
        // Checks block binding and signatures.
        if block.check_block(last)? && block.verify(self.current_controlling_identifiers()?)? {
            let mut blocks = self.blocks.clone();
            blocks.push(block);
            Ok(MicroLedger {
                blocks: blocks.to_vec(),
            })
        } else {
            Err(Error::MicroError("Wrong block".into()))
        }
    }

    fn get_last_block(&self) -> Option<&Block<I, D, C>> {
        self.blocks.last().map(|last| &last.block)
    }

    /// Returns copy of sub-microledger which last block matches the given fingerprint.
    fn at(&self, block_id: &D) -> Option<Self> {
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

    fn current_controlling_identifiers(&self) -> Result<Option<Vec<C>>> {
        Ok(self
            .get_last_block()
            .map(|block| block.controlling_identifiers.clone()))
    }

    /// Returns block of given fingerprint
    pub fn get_block(&self, fingerprint: &SelfAddressingPrefix) -> Result<Block<I, D, C>> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Serialization::serialize(&b.block)))
            .map(|b| b.block.clone())
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    fn get_block_provider(
        &self,
        fingerprint: &SelfAddressingPrefix,
    ) -> Result<(Block<I, D, C>, P)> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Serialization::serialize(&b.block)))
            .map(|b| (b.block.clone(), b.attached_seal.clone()))
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    pub fn get_seal_datums(&self, fingerprint: &SelfAddressingPrefix) -> Result<Vec<String>> {
        let (block, provider) = self.get_block_provider(fingerprint)?;
        Ok(block
            .seals
            .iter()
            .map(|s| provider.get(s).unwrap())
            .collect())
    }
}

#[cfg(test)]
pub mod test {
    use keri::prefix::{BasicPrefix, SelfSigningPrefix};
    use said::prefix::SelfAddressingPrefix;

    use crate::{
        block::Block, microledger::MicroLedger, seal_provider::SealsAttachement,
        seals::AttachmentSeal,
    };

    #[test]
    fn test_microledger_traversing() {
        type MicroledgerExample = MicroLedger<
            AttachmentSeal,
            SelfAddressingPrefix,
            BasicPrefix,
            SelfSigningPrefix,
            SealsAttachement,
        >;

        type BlockType = Block<AttachmentSeal, SelfAddressingPrefix, BasicPrefix>;

        let serialized_microledger = r#"{"bs":[{"bl":{"s":["ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4"],"ci":["DHwi3fny5p1YTLVBh6sTFfGc6SVo0-WmqTBp8bRxftis"]},"si":["0Bcjzq7Fn2ObJeaY95TBv9_IBExN-9RxYWzbGcsW9wQDyvzQKaXhVts_5ZzxLzZCrBJm2RRkqDIJQym_h_NY_TAw"],"at":{"ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4":"some message"}},{"bl":{"s":["E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I"],"p":"E_j0QDlIx9jGOndGyZsamzGsTSIcRgXEPoFGkO4sGpXI","ci":["D4aYRwAOKukrceiJGMFw_x8cG__VWbJKsPSE95FfSGb8"]},"si":["0BaSVviL57qpKwd__u844J_-XgGjHZ3uxk9tB2FovH6KJId8BNvYop2jgOJb3ttJCasLE1DwYbxopyw8QmywOlAQ"],"at":{"E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I":"one more message"}},{"bl":{"s":["EJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8"],"p":"Er1nlzyvdg_aEC-jM8rsf5guXAA5HSkJ-cZQjJmejZV0","ci":["Dl0XOCM8-xCHuf9nFZllJmKCWoBZNy9gf6uopXxQLuho"]},"si":["0BZUlP9DaTbQK4sxFpa-M7uU9cPvqPd3geqH2WTHBVrJqJ8QIcd37Bf6jwp9JXesKkmMOudhcwcnEP0hLBLu4JDg"],"at":{"EJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8":"again, one more message"}}]}"#;
        let deserialize_microledger: MicroledgerExample =
            serde_json::from_str(&serialized_microledger).unwrap();
        assert_eq!(3, deserialize_microledger.blocks.len());

        let second_block_id: SelfAddressingPrefix = "Er1nlzyvdg_aEC-jM8rsf5guXAA5HSkJ-cZQjJmejZV0"
            .parse()
            .unwrap();

        // test `at` function
        let at_micro = deserialize_microledger.at(&second_block_id).unwrap();
        assert_eq!(at_micro.blocks.len(), 2);

        // test `get_last_block`
        let last = deserialize_microledger.get_last_block().unwrap().clone();
        let sed_last = r#"{"s":["EJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8"],"p":"Er1nlzyvdg_aEC-jM8rsf5guXAA5HSkJ-cZQjJmejZV0","ci":["Dl0XOCM8-xCHuf9nFZllJmKCWoBZNy9gf6uopXxQLuho"]}"#;
        let block: BlockType = serde_json::from_str(sed_last).unwrap();
        assert_eq!(last, block);

        assert_ne!(last, at_micro.get_last_block().unwrap().to_owned());

        // test `get_seals_datum`
        let seals = deserialize_microledger
            .get_seal_datums(&second_block_id)
            .unwrap();
        assert_eq!(seals.len(), 1);
        assert_eq!(seals[0], "one more message");
    }
}
