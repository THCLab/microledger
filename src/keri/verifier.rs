use std::sync::Arc;

use keri::{
    database::SledEventDatabase, event::sections::seal::EventSeal,
    event_message::signature::Nontransferable, processor::validator::EventValidator,
};

use crate::{microledger::Result, verifier::Verifier};

use super::signature::KeriSignature;

pub struct KeriVerifier(EventValidator);

impl Verifier for KeriVerifier {
    type Signature = KeriSignature;

    fn verify(&self, data: &[u8], s: Vec<Self::Signature>) -> Result<bool> {
        Ok(s.into_iter()
            .all(|sig| self.0.verify(data, &sig.into()).is_ok()))
    }
}

impl Into<keri::event_message::signature::Signature> for KeriSignature {
    fn into(self) -> keri::event_message::signature::Signature {
        use keri::event_message::signature::{Signature, SignerData};
        match self {
            KeriSignature::Transferable(id, sn, dig, sigs) => Signature::Transferable(
                SignerData::EventSeal(EventSeal {
                    prefix: id,
                    sn,
                    event_digest: dig,
                }),
                sigs.into_iter().map(|s| s.into()).collect(),
            ),
            KeriSignature::Nontransferable(bp, ssp) => {
                Signature::NonTransferable(Nontransferable::Couplet(vec![(bp, ssp)]))
            }
        }
    }
}

impl KeriVerifier {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        KeriVerifier(EventValidator::new(db))
    }
}

#[cfg(test)]
pub mod test {

    use std::sync::Arc;

    use cesrox::primitives::codes::self_signing::SelfSigning;
    use ed25519_dalek::ExpandedSecretKey;
    use keri::{
        database::SledEventDatabase,
        keys::PublicKey,
        prefix::{BasicPrefix, SelfSigningPrefix},
        processor::basic_processor::BasicProcessor,
    };
    use rand::rngs::OsRng;
    use sai::derivation::SelfAddressing;
    use tempfile::Builder;

    use crate::{
        block::{Block, SignedBlock},
        digital_fingerprint::DigitalFingerprint,
        keri::{
            controlling_identifier::ControllingIdentifier, signature::KeriSignature,
            verifier::KeriVerifier,
        },
        microledger::MicroLedger,
        seal_bundle::{SealBundle, SealData},
        seals::Seal,
        Encode,
    };

    #[test]
    fn test_signed_block() {
        #[cfg(feature = "keri")]
        use crate::keri::verifier::KeriVerifier;
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let event_processor = BasicProcessor::new(Arc::clone(&db), None);
        let validator = Arc::new(KeriVerifier::new(db));

        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, sk) = (kp.public, kp.secret);
        let pref = BasicPrefix::Ed25519(PublicKey::new(pk.as_bytes().to_vec()));
        let bp = ControllingIdentifier::Keri(keri::prefix::IdentifierPrefix::Basic(pref.clone()));

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
                .sign(data, &pk)
                .as_ref()
                .to_vec()
        };
        let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev = Some(DigitalFingerprint::SelfAddressing(
            SelfAddressing::Blake3_256.derive("exmaple".as_bytes()),
        ));
        let block = Block::new(vec![Seal::Attached(seal)], prev, vec![(bp)]);

        let sig = KeriSignature::Nontransferable(
            pref,
            SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
        );

        let signed = block.to_signed_block(vec![sig]);
        assert!(signed.verify(validator, None).unwrap());

        let signed_block_cesr = signed.to_cesr().unwrap();

        let block_from_cesr =
            SignedBlock::<ControllingIdentifier, KeriSignature>::from_cesr(&signed_block_cesr)
                .unwrap();
        assert_eq!(block_from_cesr.block, signed.block);
        assert_eq!(block_from_cesr.signatures, signed.signatures);
    }

    #[test]
    fn test_microledger() {
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let event_processor = BasicProcessor::new(Arc::clone(&db), None);
        let validator = Arc::new(KeriVerifier::new(db));

        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, sk) = (kp.public, kp.secret);

        let pref = BasicPrefix::Ed25519(PublicKey::new(pk.as_bytes().to_vec()));
        let bp = ControllingIdentifier::Keri(keri::prefix::IdentifierPrefix::Basic(pref.clone()));

        let mut microledger = MicroLedger::new(validator);
        let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals);

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
                .sign(data, &pk)
                .as_ref()
                .to_vec()
        };

        let signatures = KeriSignature::Nontransferable(
            pref.clone(),
            SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
        );
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

        let signatures = KeriSignature::Nontransferable(
            pref.clone(),
            SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
        );
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

        let signatures = KeriSignature::Nontransferable(
            pref,
            SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
        );
        let signed = block.to_signed_block(vec![signatures]);
        microledger.anchor(signed).unwrap();

        // let blocks = microledger.blocks;
        // println!("{}", serde_json::to_string(&blocks).unwrap());
        println!(
            "{}",
            String::from_utf8(microledger.to_cesr().unwrap()).unwrap()
        );
    }

    #[test]
    fn test_microledger_traversing() {
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let event_processor = BasicProcessor::new(Arc::clone(&db), None);
        let validator = Arc::new(KeriVerifier::new(db));

        let serialized_microledger = r#"{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}-CABDDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N0BA3mV0Ga-e3Ly2yAy2w9PgUbrgglzuDFBh8TQXal1zQlsOYFxWf3x6uqpiVpuiKMddnmMEWGF0iTFgrw07UGSYO{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"p":"AEL_OPgFBnvQ45jaVqygWfEDbdkaPaC_x81yhh8nOmerL","ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}-CABDDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N0BDQb_cVMsBGFgtxj5JakS1icx3ubheCOvth4U-c9hRsL38msumM7xJHmaTXpCNcNTDRtNw8tS6O5Ki9EuAKxecD{"s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"],"p":"AEP-tb9xGrwyHlm_ekDIQIAsvj2lp_el0p2zfUcXEM30I","ci":["DDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N"]}-CABDDSJCC9yQkd62kcQk-iW9xA20mgrCrTfWffDiGE_H-_N0BDYbWMxzpoec8aYKe0kdE9bUoBizBQZ1R8kZiFbyA9P2iXH5LBaMj9vrbZSxlWQspPfDIDlsitrEYkxuYjc4oQG"#;

        let deserialize_microledger = MicroLedger::<KeriSignature, _, _>::new_from_cesr(
            serialized_microledger.as_bytes(),
            validator,
        )
        .unwrap();
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
        let block: Block<ControllingIdentifier> = serde_json::from_str(sed_last).unwrap();
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
