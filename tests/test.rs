use ::microledger::microledger::MicroLedger;
use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    keys::{PrivateKey, PublicKey},
    prefix::{BasicPrefix, SelfSigningPrefix},
};
use microledger::{
    error::Error, seal_provider::SealsAttachement, seals::AttachmentSeal, Serialization,
};
use rand::rngs::OsRng;
use said::prefix::SelfAddressingPrefix;

fn generate_key_pair() -> (PublicKey, PrivateKey) {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    (vk, sk)
}

type MicroledgerExample = MicroLedger<
    AttachmentSeal,
    SelfAddressingPrefix,
    BasicPrefix,
    SelfSigningPrefix,
    SealsAttachement,
>;

#[test]
fn test() -> Result<(), Error> {
    let mut microledger: MicroledgerExample = MicroLedger::new();
    let (pk, sk) = generate_key_pair();

    let payload = "some message";
    let bp = Basic::Ed25519.derive(pk);

    let mut block = microledger.pre_anchor_block(vec![], vec![bp]);
    block.attach(payload.as_bytes())?;

    // Sign block, attach signature and seal provider.
    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s]);

    // Attach block to microledger.
    microledger = microledger.anchor(signed_block)?;
    assert_eq!(1, microledger.blocks.len());

    // Prepeare data for new block.
    let payload = "another message";
    let (npk, _nsk) = generate_key_pair();
    let nbp = Basic::Ed25519.derive(npk);

    let mut block0 = microledger.pre_anchor_block(vec![], vec![nbp.clone()]);
    block0.attach(payload.as_bytes())?;

    // try to append block with wrong signature
    let (_wrong_pk, wrong_sk) = generate_key_pair();
    let signature_raw = wrong_sk.sign_ed(&block0.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);

    let signed_block0 = block0.to_signed_block(vec![s]);
    let result = microledger.anchor(signed_block0);
    assert!(result.is_err());
    assert_eq!(1, microledger.blocks.len());

    // Now sign block the same block with proper keys and append it.
    let mut block1 = microledger.pre_anchor_block(vec![], vec![nbp]);
    block1.attach(payload.as_bytes())?;

    let signature_raw = sk.sign_ed(&block1.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block1 = block1.to_signed_block(vec![s]);
    let microledger0 = microledger.anchor(signed_block1)?;

    assert_eq!(2, microledger0.blocks.len());
    assert_eq!(1, microledger.blocks.len());

    // Try to add concurent block.
    let payload = "one more message";
    let (nnpk, nnsk) = generate_key_pair();
    let nnbp = Basic::Ed25519.derive(nnpk);

    let mut block2 = microledger.pre_anchor_block(vec![], vec![nnbp]);
    block2.attach(payload.as_bytes())?;

    let signature_raw = sk.sign_ed(&block2.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block2 = block2.to_signed_block(vec![s]);
    let microledger1 = microledger.anchor(signed_block2)?;

    assert_eq!(2, microledger1.blocks.len());
    assert_eq!(1, microledger.blocks.len());

    let payload = "again, one more message";
    let (nnpk, _nnsk) = generate_key_pair();
    let nnbp = Basic::Ed25519.derive(nnpk);

    let mut block3 = microledger1.pre_anchor_block(vec![], vec![nnbp]);
    block3.attach(payload.as_bytes())?;

    let signature_raw = nnsk.sign_ed(&block3.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block2 = block3.to_signed_block(vec![s]);
    let microledger2 = microledger1.anchor(signed_block2)?;

    assert_eq!(3, microledger2.blocks.len());
    assert_eq!(1, microledger.blocks.len());
    println!("{}", serde_json::to_string(&microledger2).unwrap());

    Ok(())
}
