use ::microledger::microledger::MicroLedger;
use keri::{
    derivation::self_signing::SelfSigning,
    keys::{PrivateKey, PublicKey},
    prefix::SelfSigningPrefix,
};
use microledger::{
    controling_identifiers::Rules, error::Error, seal_provider::SealsAttachement, Serialization,
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
    SelfAddressingPrefix,
    SelfAddressingPrefix,
    Rules,
    SelfSigningPrefix,
    SealsAttachement,
>;

#[test]
fn test() -> Result<(), Error> {
    let mut microledger: MicroledgerExample = MicroLedger::new();
    let (pk, sk) = generate_key_pair();

    let payload = "some message";
    let rules = Rules::new(vec![pk.key()]);
    // Insert payload to SealsAttachement and get sai of inserted data
    let mut provider: SealsAttachement = SealsAttachement::new();
    let seal: SelfAddressingPrefix = provider.save(payload).unwrap();

    let block = microledger.pre_anchor_block(vec![seal.clone()], rules);

    // Sign block, attach signature and seal provider.
    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s], provider);

    // Attach block to microledger.
    microledger.anchor(signed_block)?;
    assert_eq!(1, microledger.blocks.len());

    // Prepeare data for new block.
    let payload = "another message";
    let (npk, _nsk) = generate_key_pair();
    let rules = Rules::new(vec![npk.key()]);
    let mut provider = SealsAttachement::new();
    let seal: SelfAddressingPrefix = provider.save(payload).unwrap();

    let block0 = microledger.pre_anchor_block(vec![seal.clone()], rules.clone());

    // try to append block with wrong signature
    let (_wrong_pk, wrong_sk) = generate_key_pair();
    let signature_raw = wrong_sk.sign_ed(&block0.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);

    let signed_block0 = block0.to_signed_block(vec![s], provider.clone());
    let result = microledger.anchor(signed_block0);
    assert!(result.is_err());
    assert_eq!(1, microledger.blocks.len());

    // Now sign block the same block with proper keys and append it.
    let block1 = microledger.pre_anchor_block(vec![seal.clone()], rules);
    let signature_raw = sk.sign_ed(&block1.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block1 = block1.to_signed_block(vec![s], provider);
    microledger.anchor(signed_block1)?;

    assert_eq!(2, microledger.blocks.len());

    Ok(())
}
