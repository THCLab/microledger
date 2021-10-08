use said::prefix::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::seal_bundle::SealBundle;
use crate::seals::Seal;
use crate::Serialization;
use crate::{
    block::{Block, SignedBlock},
    controling_identifiers::ControlingIdentifier,
    digital_fingerprint::DigitalFingerprint,
    signature::Signature,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize)]
pub struct MicroLedger<D, C, S>
where
    D: DigitalFingerprint + Serialize,
    C: ControlingIdentifier + Serialize + Clone,
    S: Signature + Serialize,
{
    #[serde(rename = "bs")]
    pub blocks: Vec<SignedBlock<C, D, S>>,
}

impl<D, C, S> MicroLedger<D, C, S>
where
    D: DigitalFingerprint + Serialize + Clone,
    C: ControlingIdentifier + Serialize + Clone,
    S: Signature + Serialize + Clone,
{
    pub fn new() -> Self {
        MicroLedger { blocks: vec![] }
    }

    pub fn append_block(&self, signed_block: SignedBlock<C, D, S>) -> Result<MicroLedger<D, C, S>> {
        let mut blocks = self.blocks.clone();
        blocks.append(&mut vec![signed_block]);
        Ok(Self { blocks })
    }

    pub fn pre_anchor_block(
        &self,
        controlling_identifiers: Vec<C>,
        seal_bundle: &SealBundle,
    ) -> Block<D, C>
    where
        D: DigitalFingerprint + Serialize,
        C: ControlingIdentifier + Serialize + Clone,
        S: Signature + Serialize,
    {
        let prev = self
            .blocks
            .last()
            .map(|sb| D::derive(&Serialization::serialize(&sb.block)));

        let seals = seal_bundle.get_fingerprints();
        Block::new(seals, prev, controlling_identifiers)
    }

    pub fn anchor(&self, block: SignedBlock<C, D, S>) -> Result<Self> {
        let last = self.get_last_block();
        // Checks block binding and signatures.
        if block.check_block(last)? && block.verify(self.current_controlling_identifiers()?)? {
            self.append_block(block)
        } else {
            Err(Error::MicroError("Wrong block".into()))
        }
    }

    fn get_last_block(&self) -> Option<&Block<D, C>> {
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
    pub fn get_block(&self, fingerprint: &SelfAddressingPrefix) -> Result<Block<D, C>> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Serialization::serialize(&b.block)))
            .map(|b| b.block.clone())
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    fn get_block_by_fingerprint(&self, fingerprint: &D) -> Result<SignedBlock<C, D, S>> {
        self.blocks
            .clone()
            .into_iter()
            .find(|b| fingerprint.verify_binding(&Serialization::serialize(&b.block)))
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    pub fn get_seal_datums(&self, fingerprint: &D) -> Result<Vec<String>> {
        let block = self.get_block_by_fingerprint(fingerprint)?;
        let found_data: Result<Vec<_>> = block
            .block
            .seals
            .iter()
            .map(|s| match s {
                Seal::Attached(sai) => block
                    .attached_seal
                    .get(&sai.to_string())
                    .ok_or_else(|| Error::BlockError("Can't find attached data".into())),
            })
            .collect();
        found_data
    }
}

#[cfg(test)]
pub mod test {
    use keri::prefix::{BasicPrefix, SelfSigningPrefix};
    use said::prefix::SelfAddressingPrefix;

    use crate::{block::Block, microledger::MicroLedger};

    #[test]
    fn test_microledger_traversing() {
        type MicroledgerExample = MicroLedger<SelfAddressingPrefix, BasicPrefix, SelfSigningPrefix>;

        type BlockType = Block<SelfAddressingPrefix, BasicPrefix>;

        let serialized_microledger = r#"{"bs":[{"bl":{"s":["AELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4"],"ci":["DjUa-x_AosMd8MpJ_DEj2HAfADxTpViPWi-bs47wld6w"]},"si":["0BVDIxO0hQbEa1a83PikJbAc2vZ8R0rXUS21PnoyD5Bs1zKnrS-vnJ6WWRoVspDmq6Camio89bUAT0B04DrI_lCw"],"at":{"attachements":{"ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4":"some message"}}},{"bl":{"s":["AE6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I"],"p":"EVatnlUNghpjIrUnP8nBF3h4-62i1j1VEX_agal9YbWI","ci":["DOpO_5SG-mg9-Me_nqAqQgc-6si7kNmtuHLNTW3rNvDE"]},"si":["0B36jjwROTKGFxxI6mNgnmKPTu2eUbH0f322eMq44BzHCtJweHEo0Q4P2NYJWeZGQ6SbTEyAE9oewjPITtupftCg"],"at":{"attachements":{"E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I":"one more message"}}},{"bl":{"s":["AEJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8"],"p":"EtL-bxZmNJQQwrQH5pABTn-RpfCriJhThyDwlDYzDGTk","ci":["DA0V3PfIaXdoHYWIQVrLAS262ZZuG7hquOno8a5y65vQ"]},"si":["0BLL3w9broV8Trn9sNQyhYOqXDpC51thWMLWNgPHScFK_L69djevLXvsgt551MDuJ3dSACi6iFpYP5Ua-P9dQCCw"],"at":{"attachements":{"EJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8":"again, one more message"}}}]}"#;
        let deserialize_microledger: MicroledgerExample =
            serde_json::from_str(&serialized_microledger).unwrap();
        assert_eq!(3, deserialize_microledger.blocks.len());

        let second_block_id: SelfAddressingPrefix = "EtL-bxZmNJQQwrQH5pABTn-RpfCriJhThyDwlDYzDGTk"
            .parse()
            .unwrap();

        // test `at` function
        let at_micro = deserialize_microledger.at(&second_block_id).unwrap();
        assert_eq!(at_micro.blocks.len(), 2);

        // test `get_last_block`
        let last = deserialize_microledger.get_last_block().unwrap().clone();
        let sed_last = r#"{"s":["AEJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8"],"p":"EtL-bxZmNJQQwrQH5pABTn-RpfCriJhThyDwlDYzDGTk","ci":["DA0V3PfIaXdoHYWIQVrLAS262ZZuG7hquOno8a5y65vQ"]}"#;
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
