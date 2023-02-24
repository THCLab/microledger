use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::seal_bundle::SealBundle;
use crate::Serialization;
use crate::{
    block::{Block, SignedBlock},
    controlling_identifier::ControllingIdentifier,
    digital_fingerprint::DigitalFingerprint,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct MicroLedger {
    #[serde(rename = "bs")]
    pub blocks: Vec<SignedBlock>,
}

impl MicroLedger {
    pub fn new() -> Self {
        MicroLedger { blocks: vec![] }
    }

    pub fn append_block(&self, signed_block: SignedBlock) -> Result<MicroLedger> {
        let mut blocks = self.blocks.clone();
        blocks.append(&mut vec![signed_block]);
        Ok(Self { blocks })
    }

    pub fn pre_anchor_block(
        &self,
        controlling_identifiers: Vec<ControllingIdentifier>,
        seal_bundle: &SealBundle,
    ) -> Block {
        let prev = self
            .blocks
            .last()
            .map(|sb| DigitalFingerprint::derive(&Serialization::serialize(&sb.block)));

        let seals = seal_bundle.get_fingerprints();
        Block::new(seals, prev, controlling_identifiers)
    }

    pub fn anchor(&self, block: SignedBlock) -> Result<Self> {
        let last = self.get_last_block();
        // Checks block binding and signatures.
        if block.check_block(last)? && block.verify(self.current_controlling_identifiers()?)? {
            self.append_block(block)
        } else {
            Err(Error::MicroError("Wrong block".into()))
        }
    }

    fn get_last_block(&self) -> Option<&Block> {
        self.blocks.last().map(|last| &last.block)
    }

    /// Returns copy of sub-microledger which last block matches the given fingerprint.
    fn at(&self, block_id: &DigitalFingerprint) -> Option<Self> {
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

    fn current_controlling_identifiers(&self) -> Result<Option<Vec<ControllingIdentifier>>> {
        Ok(self
            .get_last_block()
            .map(|block| block.controlling_identifiers.clone()))
    }

    /// Returns block of given fingerprint
    pub fn get_block(&self, fingerprint: DigitalFingerprint) -> Result<Block> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Serialization::serialize(&b.block)))
            .map(|b| b.block.clone())
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    fn get_block_by_fingerprint(&self, fingerprint: &DigitalFingerprint) -> Result<SignedBlock> {
        self.blocks
            .clone()
            .into_iter()
            .find(|b| fingerprint.verify_binding(&Serialization::serialize(&b.block)))
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    // pub fn get_seal_datums(&self, fingerprint: &DigitalFingerprint) -> Result<Vec<String>> {
    //     let block = self.get_block_by_fingerprint(fingerprint)?;
    //     let found_data: Result<Vec<_>> = block
    //         .block
    //         .seals
    //         .iter()
    //         .map(|s| match s {
    //             Seal::Attached(sai) => block
    //                 .attached_seal
    //                 .get(&sai.to_string())
    //                 .ok_or_else(|| Error::BlockError("Can't find attached data".into())),
    //         })
    //         .collect();
    //     found_data
    // }
}

#[cfg(test)]
pub mod test {

    use cesrox::primitives::codes::self_signing::SelfSigning;
    use ed25519_dalek::ExpandedSecretKey;
    use keri::{prefix::{BasicPrefix, SelfSigningPrefix}, keys::PublicKey};
    use rand::rngs::OsRng;
    use sai::derivation::SelfAddressing;

    use crate::{block::{Block, SignedBlock}, digital_fingerprint::DigitalFingerprint, microledger::MicroLedger, controlling_identifier::ControllingIdentifier, seals::Seal, Serialization, seal_bundle::{SealBundle, SealData}, signature::Signature};

     #[test]
    fn test_microledger() {
        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, sk) = (kp.public, kp.secret);
        let bp = ControllingIdentifier::Basic(BasicPrefix::Ed25519(PublicKey::new(
            pk.as_bytes().to_vec(),
        )));

        let microledger = MicroLedger::new();
        let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals);

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
        };

        let signatures = Signature::SelfSigning(SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.serialize())));
        let signed = block.to_signed_block(vec![signatures]);
        let microledger = microledger.anchor(signed).unwrap();

        let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![(bp)], &seals);

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
        };

        let signatures = Signature::SelfSigning(SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.serialize())));
        let signed = block.to_signed_block(vec![signatures]);
        let microledger = microledger.anchor(signed).unwrap();

        let blocks = microledger.blocks;
        println!("{}", serde_json::to_string(&blocks).unwrap());

    }

    #[test]
    fn test_microledger_traversing() {
        let serialized_microledger = r#"{"bs":[
            {"bl":{"s":["AELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4"],"ci":["ADzfIfArvcpqlhWPWALcqnf_VtQ4gX9Bg_av9e4dB7ciI"]},"si":["A0B_vrdVGJ19PJkIWT4KIJ2vnUAMUNS-T-A2FC3r1oWE84sBd0t3QFt3iAWtLq9TZ9ecHe_G6VX1y5oVQDDLFijCw"],"at":{"attachements":{"ELw56P7ccBSkFj-THMErcH7RFX2Ph1fDUfQ1ErEmDuD4":"some message"}}},
            {"bl":{"s":["AE6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I"],"p":"AEa57Kf0zAZaVEO3cuWXEe2ihPA_i4FVq3PCyDNtVitgg","ci":["ADjdeUHPIYwMDlZJs0cfE60NDN2R4Eb9OmtKuNCmORWdI"]},"si":["A0B62_hffohOXC7luK-h3TwEfUGD4BpEX8kjEXwFpGA-I3BBjG11IslWD2umDZubf1a-XmQZxgwdQB0UPIf5MkuDg"],"at":{"attachements":{"E6AVF6hEJH0NS-bTZvfKac9EIDXfmpVSTzvzyKGGmn9I":"one more message"}}},
            {"bl":{"s":["AEJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8"],"p":"AEhvkz6v16nXuA9cD0yvkqPAcLJd1ajjiTGlWO9WfJZM4","ci":["ADZdoBkHaXfWqe63hMDgi2KG2CLAx3nJ6rjSn_aUxKd4w"]},"si":["A0B_gymZvjym-bC2a-n4Kx_FEszNllgxNJwYe0SuDpwWX8vtXAzJGJ5OZZxbHPrgfKwfiWHMNE_pVmzB1TjK8XUCw"],"at":{"attachements":{"EJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8":"again, one more message"}}}
        ]}"#;

        let deserialize_microledger: MicroLedger =
            serde_json::from_str(serialized_microledger).unwrap();
        assert_eq!(3, deserialize_microledger.blocks.len());

        let second_block_id: DigitalFingerprint = "AEhvkz6v16nXuA9cD0yvkqPAcLJd1ajjiTGlWO9WfJZM4"
            .parse()
            .unwrap();

        // test `at` function
        let at_micro = deserialize_microledger.at(&second_block_id).unwrap();
        assert_eq!(at_micro.blocks.len(), 2);

        // test `get_last_block`
        let last = deserialize_microledger.get_last_block().unwrap().clone();
        let sed_last = r#"{"s":["AEJLZcnDF6gCZdODVgYOczNCluO3CkJa0yONOkXvXiVO8"],"p":"AEhvkz6v16nXuA9cD0yvkqPAcLJd1ajjiTGlWO9WfJZM4","ci":["ADZdoBkHaXfWqe63hMDgi2KG2CLAx3nJ6rjSn_aUxKd4w"]}"#;
        let block: Block = serde_json::from_str(sed_last).unwrap();
        assert_eq!(last, block);

        assert_ne!(last, at_micro.get_last_block().unwrap().to_owned());

        // // test `get_seals_datum`
        // let seals = deserialize_microledger
        //     .get_seal_datums(&second_block_id)
        //     .unwrap();
        // assert_eq!(seals.len(), 1);
        // assert_eq!(seals[0], "one more message");
    }
}
