use ::microledger::{microledger::MicroLedger, seal_provider::DummyProvider};
use keri::{
    derivation::self_signing::SelfSigning,
    keys::{PrivateKey, PublicKey},
    prefix::SelfSigningPrefix,
};
use microledger::{controling_identifiers::Rules, Serialization};
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
fn test() {
    let mut microledger: MicroLedger<
        SelfAddressingPrefix,
        SelfAddressingPrefix,
        Rules,
        DummyProvider,
        SelfSigningPrefix,
    > = MicroLedger::new();
    let (pk, sk) = generate_key_pair();
    let (npk, _nsk) = generate_key_pair();
    let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
    let rules = Rules::new(vec![pk.key()]);
    let provider = DummyProvider::new().insert((seal.to_string(), "example".to_string()));
    let block = microledger.pre_anchor_block(vec![seal.clone()], provider, rules);
    println!("{}", String::from_utf8(block.serialize()).unwrap());

    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s], &[(seal.to_string(), "example".to_string())]);
    microledger.anchor(signed_block);

    let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
    let rules = Rules::new(vec![npk.key()]);
    let provider = DummyProvider::new().insert((seal.to_string(), "example".to_string()));
    let block = microledger.pre_anchor_block(vec![seal.clone()], provider, rules);
    println!("{}", String::from_utf8(block.serialize()).unwrap());
    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s], &[(seal.to_string(), "example".to_string())]);
    microledger.anchor(signed_block);

    assert_eq!(2, microledger.blocks.len());
}
