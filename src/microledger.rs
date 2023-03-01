use serde::{Deserialize, Serialize};

use crate::Encode;
use crate::error::Error;
use crate::seal_bundle::SealBundle;
use crate::signature::{Verify, KeriSignature};
use crate::{
    block::{Block, SignedBlock},
    controlling_identifier::ControllingIdentifier,
    digital_fingerprint::DigitalFingerprint,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct MicroLedger<S: Verify + Serialize> {
    #[serde(rename = "bs")]
    pub blocks: Vec<SignedBlock<S>>,
}

impl<S: Verify + Serialize +  Clone> MicroLedger<S> {
    pub fn new() -> Self {
        MicroLedger { blocks: vec![] }
    }

    pub fn append_block(&mut self, signed_block: SignedBlock<S>) -> Result<()> {
        self.blocks.append(&mut vec![signed_block]);
        Ok(())
    }

    pub fn pre_anchor_block(
        &self,
        controlling_identifiers: Vec<ControllingIdentifier>,
        seal_bundle: &SealBundle,
    ) -> Block {
        let prev = self
            .blocks
            .last()
            .map(|sb| DigitalFingerprint::derive(&Encode::encode(&sb.block)));

        let seals = seal_bundle.get_fingerprints();
        Block::new(seals, prev, controlling_identifiers)
    }

    pub fn anchor(&mut self, block: SignedBlock<S>) -> Result<()> {
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
            .iter()
            .position(|b| block_id.verify_binding(&Encode::encode(&b.block)));
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
            .find(|b| fingerprint.verify_binding(&Encode::encode(&b.block)))
            .map(|b| b.block.clone())
            .ok_or_else(|| Error::MicroError("No block of given fingerprint".into()))
    }

    fn get_block_by_fingerprint(&self, fingerprint: &DigitalFingerprint) -> Result<&SignedBlock<S>> {
        self.blocks
            .iter()
            .find(|b| fingerprint.verify_binding(&Encode::encode(&b.block)))
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
impl MicroLedger<KeriSignature> {
    pub fn from_cesr(stream: &[u8]) -> Result<Self> {
        let (rest, parsed_stream) = cesrox::parse_many(stream).unwrap();
        let mut microledger = MicroLedger::new();
        parsed_stream.into_iter().for_each(|pd| microledger.append_block(pd.into()).unwrap());
        Ok(microledger)
    }

    pub fn to_cesr(&self) -> Result<Vec<u8>> {
        Ok(self.blocks
            .iter()
            .map(|bl| bl.to_cesr().unwrap())
            .flatten()
            .collect())
    }
}

#[cfg(test)]
pub mod test {

    use cesrox::primitives::codes::self_signing::SelfSigning;
    use ed25519_dalek::ExpandedSecretKey;
    use keri::{prefix::{BasicPrefix, SelfSigningPrefix}, keys::PublicKey};
    use rand::rngs::OsRng;

    use crate::{block::{Block, SignedBlock}, digital_fingerprint::DigitalFingerprint, microledger::MicroLedger, controlling_identifier::ControllingIdentifier, seals::Seal, seal_bundle::{SealBundle, SealData}, signature::KeriSignature, Encode};

     #[test]
    fn test_microledger() {
        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, sk) = (kp.public, kp.secret);

        let pref = BasicPrefix::Ed25519(PublicKey::new(pk.as_bytes().to_vec()));
        let bp = ControllingIdentifier::Keri(keri::prefix::IdentifierPrefix::Basic(pref.clone()));

        let mut microledger = MicroLedger::new();
        let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals);

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
        };

        let signatures = KeriSignature::Nontransferable(pref.clone(), SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())));
        let signed = block.to_signed_block(vec![signatures]);
        microledger.anchor(signed).unwrap();

        let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals);

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
        };

        let signatures = KeriSignature::Nontransferable(pref.clone(), SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())));
        let signed = block.to_signed_block(vec![signatures]);
        microledger.anchor(signed).unwrap();

         let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![(bp)], &seals);

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
        };

        let signatures = KeriSignature::Nontransferable(pref, SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())));
        let signed = block.to_signed_block(vec![signatures]);
        microledger.anchor(signed).unwrap();

        // let blocks = microledger.blocks;
        // println!("{}", serde_json::to_string(&blocks).unwrap());
        println!("{}", String::from_utf8(microledger.to_cesr().unwrap()).unwrap());

    }

    #[test]
    fn test_microledger_traversing() {
        let serialized_microledger = r#"{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}-CABDDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N0BA3mV0Ga-e3Ly2yAy2w9PgUbrgglzuDFBh8TQXal1zQlsOYFxWf3x6uqpiVpuiKMddnmMEWGF0iTFgrw07UGSYO{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"p":"AEL_OPgFBnvQ45jaVqygWfEDbdkaPaC_x81yhh8nOmerL","ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}-CABDDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N0BDQb_cVMsBGFgtxj5JakS1icx3ubheCOvth4U-c9hRsL38msumM7xJHmaTXpCNcNTDRtNw8tS6O5Ki9EuAKxecD{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"p":"AEP-tb9xGrwyHlm_ekDIQIAsvj2lp_el0p2zfUcXEM30I","ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}-CABDDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N0BDYbWMxzpoec8aYKe0kdE9bUoBizBQZ1R8kZiFbyA9P2iXH5LBaMj9vrbZSxlWQspPfDIDlsitrEYkxuYjc4oQG"#;

        let deserialize_microledger  =
            MicroLedger::<KeriSignature>::from_cesr(serialized_microledger.as_bytes()).unwrap();
        assert_eq!(3, deserialize_microledger.blocks.len());

        let second_block_id: DigitalFingerprint = "AEP-tb9xGrwyHlm_ekDIQIAsvj2lp_el0p2zfUcXEM30I"
            .parse()
            .unwrap();

        // test `at` function
        let at_micro = deserialize_microledger.at(&second_block_id).unwrap();
        assert_eq!(at_micro.blocks.len(), 2);

        // test `get_last_block`
        let last = deserialize_microledger.get_last_block().unwrap().clone();
        let sed_last = r#"{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"p":"AEP-tb9xGrwyHlm_ekDIQIAsvj2lp_el0p2zfUcXEM30I","ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}"#;
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
