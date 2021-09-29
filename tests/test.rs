use ::microledger::microledger::MicroLedger;
use keri::{
    derivation::self_signing::SelfSigning,
    keys::{PrivateKey, PublicKey},
    prefix::SelfSigningPrefix,
};
use microledger::{
    controling_identifiers::Rules, error::Error, seal_provider::Attachement, Serialization,
};
use rand::rngs::OsRng;
use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

fn generate_key_pair() -> (PublicKey, PrivateKey) {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    (vk, sk)
}
#[test]
fn test() -> Result<(), Error> {
    let mut microledger: MicroLedger<
        SelfAddressingPrefix,
        SelfAddressingPrefix,
        Rules,
        SelfSigningPrefix,
        Attachement,
    > = MicroLedger::new();
    let (pk, sk) = generate_key_pair();

    let payload = "some message";
    let seal = SelfAddressing::Blake3_256.derive(payload.as_bytes());
    let rules = Rules::new(vec![pk.key()]);
    // Insert payload to SealsAttachement
    let mut provider = Attachement::new();
    provider.insert(seal.to_string(), payload.to_string());

    let block = microledger.pre_anchor_block(vec![seal.clone()], rules);
    // println!("{}", String::from_utf8(block.serialize()).unwrap());

    // Sign block, attach signature and seal provider.
    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s], provider);

    // Attach block to microledger.
    microledger.anchor(signed_block)?;
    assert_eq!(1, microledger.blocks.len());

    // Prepeare data to new block.
    let payload = "another message";
    let (npk, _nsk) = generate_key_pair();
    let seal = SelfAddressing::Blake3_256.derive(payload.as_bytes());
    let rules = Rules::new(vec![npk.key()]);
    let mut provider = Attachement::new();
    provider.insert(seal.to_string(), payload.to_string());

    let block = microledger.pre_anchor_block(vec![seal.clone()], rules.clone());

    // try to append block with wrong signature
    let (_wrong_pk, wrong_sk) = generate_key_pair();
    let signature_raw = wrong_sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);

    let signed_block = block.to_signed_block(vec![s], provider.clone());
    let result = microledger.anchor(signed_block);
    assert!(result.is_err());
    assert_eq!(1, microledger.blocks.len());

    // Now sign block the same block with proper keys and append it.
    let block = microledger.pre_anchor_block(vec![seal.clone()], rules);
    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s], provider);
    microledger.anchor(signed_block)?;

    assert_eq!(2, microledger.blocks.len());
    Ok(())
}
