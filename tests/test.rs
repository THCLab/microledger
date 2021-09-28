use keri::signer::CryptoBox;
use microledger::{
    block::Block, controling_identifiers::Rules, seal_provider::DummyProvider, Serialization,
};
use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

#[test]
fn test_block_serialization() {
    let pk = CryptoBox::new().unwrap().next_pub_key.key();
    let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
    let prev: Option<SelfAddressingPrefix> =
        Some(SelfAddressing::Blake3_256.derive("exmaple".as_bytes()));
    let rules = Rules::new(vec![pk]);
    let provider = DummyProvider::new();
    let block = Block::new(seal, prev, rules, provider);
    println!("{}", String::from_utf8(block.serialize()).unwrap());

    let des: Block<SelfAddressingPrefix, SelfAddressingPrefix, Rules, DummyProvider> =
        serde_json::from_slice(&block.serialize()).unwrap();
    assert_eq!(block.serialize(), des.serialize());
}
