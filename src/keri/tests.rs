use std::sync::Arc;

use cesrox::primitives::codes::self_signing::SelfSigning;
use ed25519_dalek::ExpandedSecretKey;
use keri::{
    database::SledEventDatabase,
    event_message::signature::Nontransferable,
    keys::PublicKey,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::basic_processor::BasicProcessor,
};
use rand::rngs::OsRng;
use tempfile::Builder;

use crate::{
    block::Block,
    digital_fingerprint::DigitalFingerprint,
    keri::{verifier::KeriVerifier, KeriSignature},
    microledger::MicroLedger,
    seal_bundle::{SealBundle, SealData},
    Encode,
};

#[test]
fn test_microledger() {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let _event_processor = BasicProcessor::new(Arc::clone(&db), None);
    let validator = Arc::new(KeriVerifier::new(db));

    // generate keypair
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (pk, sk) = (kp.public, kp.secret);

    let pref = BasicPrefix::Ed25519(PublicKey::new(pk.as_bytes().to_vec()));
    let bp = keri::prefix::IdentifierPrefix::Basic(pref.clone());

    let mut microledger = MicroLedger::new(validator);
    let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
    let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals);

    let sign = |data| {
        ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
    };

    let signatures = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
        pref.clone(),
        SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
    )]));

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

    let signatures = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
        pref.clone(),
        SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
    )]));

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

    let signatures = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
        pref,
        SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
    )]));

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
    let _event_processor = BasicProcessor::new(Arc::clone(&db), None);
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
    let block: Block<IdentifierPrefix> = serde_json::from_str(sed_last).unwrap();
    assert_eq!(last, block);

    assert_ne!(last, at_micro.get_last_block().unwrap().to_owned());

    // // test `get_seals_datum`
    // let seals = deserialize_microledger
    //     .get_seal_datums(&second_block_id)
    //     .unwrap();
    // assert_eq!(seals.len(), 1);
    // assert_eq!(seals[0], "one more message");
}
