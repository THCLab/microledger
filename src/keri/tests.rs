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
use said::SelfAddressingIdentifier;
use tempfile::Builder;

use crate::{
    block::Block,
    keri::{verifier::KeriVerifier, KeriSignature},
    microledger::MicroLedger,
    seal_bundle::{SealBundle, SealData},
    Encode, Result,
};

#[test]
fn test_microledger() -> Result<()> {
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
    let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals)?;

    let sign = |data| {
        ExpandedSecretKey::from(&sk)
            .sign(data, &pk)
            .as_ref()
            .to_vec()
    };

    let encoded = block.encode()?;
    let signatures = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
        pref.clone(),
        SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&encoded)),
    )]));

    let signed = block.to_signed_block(vec![signatures]);
    microledger.anchor(signed)?;

    let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
    let block = microledger.pre_anchor_block(vec![(bp.clone())], &seals)?;

    let encoded_block = block.encode()?;
    let signatures = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
        pref.clone(),
        SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&encoded_block)),
    )]));

    let signed = block.to_signed_block(vec![signatures]);
    microledger.anchor(signed)?;

    let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
    let block = microledger.pre_anchor_block(vec![(bp)], &seals)?;

    let signatures = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
        pref,
        SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode()?)),
    )]));

    let signed = block.to_signed_block(vec![signatures]);
    microledger.anchor(signed)?;

    // let blocks = microledger.blocks;
    // println!("{}", serde_json::to_string(&blocks).unwrap());
    println!("{}", String::from_utf8(microledger.to_cesr()?).unwrap());
    Ok(())
}

#[test]
fn test_microledger_traversing() -> Result<()> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let _event_processor = BasicProcessor::new(Arc::clone(&db), None);
    let validator = Arc::new(KeriVerifier::new(db));

    let serialized_microledger = r#"{"ci":["DEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec"],"d":"EGd6asvSLN8kfMfnOMu87-wVzq0YiS7SLEqBBbKFBYOG","s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"]}-CABDEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec0BDGUXkeZdDbVqYZ75AwalK32eiirA4Cr7FIDQTNw3q516uUoq4ijEpKiwhntsuROTp4qEip6JHsy2BAxn0Jn6gO{"ci":["DEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec"],"d":"EASZwg_zixnbrxNogPpgYXh9nauPBqG4jiNVn3cYFTT_","p":"EGd6asvSLN8kfMfnOMu87-wVzq0YiS7SLEqBBbKFBYOG","s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"]}-CABDEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec0BC_Nz5biJZ2AweeAjD-Frk9niFKGzkpCVSUbcP5v-KGApeD_458aMzmexwI2bJ5EAGNGGUBcOIgGffq-iXJvhID{"ci":["DEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec"],"d":"EL-nsW-tAdE0ex7Wm9B-V3J-ilrWOXiAt-r-8713pOHO","p":"EASZwg_zixnbrxNogPpgYXh9nauPBqG4jiNVn3cYFTT_","s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"]}-CABDEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec0BCmrKe9ue57z2i9MOZrN0kMiOww2j-Tre31GKJKojYtA0pCueaXpfgt_c-BnyeFtN-vhdRo6sqfLSuJYKKmuIQF"#;

    let deserialize_microledger = MicroLedger::<KeriSignature, _, _>::new_from_cesr(
        serialized_microledger.as_bytes(),
        validator,
    )?;
    assert_eq!(3, deserialize_microledger.blocks.len());

    let second_block_id: SelfAddressingIdentifier = "EASZwg_zixnbrxNogPpgYXh9nauPBqG4jiNVn3cYFTT_"
        .parse()
        .unwrap();

    // test `at` function
    let at_micro = deserialize_microledger.at(&second_block_id).unwrap();
    assert_eq!(at_micro.blocks.len(), 2);

    // test `get_last_block`
    let last = deserialize_microledger.get_last_block().unwrap().clone();
    let sed_last = r#"{"ci":["DEsSdlPeweh0IACH9lGlp-EL_g-e3kqEu5IlFa4Zy4ec"],"d":"EL-nsW-tAdE0ex7Wm9B-V3J-ilrWOXiAt-r-8713pOHO","p":"EASZwg_zixnbrxNogPpgYXh9nauPBqG4jiNVn3cYFTT_","s":["AEOqPFj2zhoKSXkSRxeWNS7NQbvjBTreKhukIxWJKZyAP"]}"#;
    let block: Block<IdentifierPrefix> = serde_json::from_str(sed_last).unwrap();
    assert_eq!(last, block);

    assert_ne!(last, at_micro.get_last_block().unwrap().to_owned());

    // // test `get_seals_datum`
    // let seals = deserialize_microledger
    //     .get_seal_datums(&second_block_id)
    //     .unwrap();
    // assert_eq!(seals.len(), 1);
    // assert_eq!(seals[0], "one more message");
    Ok(())
}
