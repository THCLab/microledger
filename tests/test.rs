use ::microledger::microledger::MicroLedger;
use keri::{
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    keys::{PrivateKey, PublicKey},
    prefix::{BasicPrefix, Prefix, SelfSigningPrefix},
};
use microledger::{
    error::Error,
    seal_bundle::{SealBundle, SealData},
    Serialization,
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

type MicroledgerExample = MicroLedger<SelfAddressingPrefix, BasicPrefix, SelfSigningPrefix>;

#[test]
fn test() -> Result<(), Error> {
    let mut microledger: MicroledgerExample = MicroLedger::new();
    let (pk, sk) = generate_key_pair();

    let payload = "some message";
    let bp = Basic::Ed25519.derive(pk);

    let seal_bundle = SealBundle::new().attach(SealData::AttachedData(payload.to_string()));

    let block = microledger.pre_anchor_block(vec![bp], &seal_bundle);

    // Sign block, attach signature and seal provider.
    let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block = block.to_signed_block(vec![s], &seal_bundle);

    // Attach block to microledger.
    microledger = microledger.anchor(signed_block)?;
    assert_eq!(1, microledger.blocks.len());

    // Prepeare data for new block.
    let payload = "another message";
    let (npk, _nsk) = generate_key_pair();
    let nbp = Basic::Ed25519.derive(npk);

    let seal_bundle = SealBundle::new().attach(SealData::AttachedData(payload.to_string()));

    let block0 = microledger.pre_anchor_block(vec![nbp.clone()], &seal_bundle);

    // try to append block with wrong signature
    let (_wrong_pk, wrong_sk) = generate_key_pair();
    let signature_raw = wrong_sk.sign_ed(&block0.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);

    let signed_block0 = block0.to_signed_block(vec![s], &seal_bundle);
    let result = microledger.anchor(signed_block0);
    assert!(result.is_err());
    assert_eq!(1, microledger.blocks.len());

    // Now sign block the same block with proper keys and append it.
    let block1 = microledger.pre_anchor_block(vec![nbp], &seal_bundle);

    let signature_raw = sk.sign_ed(&block1.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block1 = block1.to_signed_block(vec![s], &seal_bundle);
    let microledger0 = microledger.anchor(signed_block1)?;

    assert_eq!(2, microledger0.blocks.len());
    assert_eq!(1, microledger.blocks.len());

    // Try to add concurent block.
    let payload = "one more message";
    let (nnpk, nnsk) = generate_key_pair();
    let nnbp = Basic::Ed25519.derive(nnpk);

    let seal_bundle = SealBundle::new().attach(SealData::AttachedData(payload.to_string()));

    let block2 = microledger.pre_anchor_block(vec![nnbp], &seal_bundle);

    let signature_raw = sk.sign_ed(&block2.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block2 = block2.to_signed_block(vec![s], &seal_bundle);
    let microledger1 = microledger.anchor(signed_block2)?;

    assert_eq!(2, microledger1.blocks.len());
    assert_eq!(1, microledger.blocks.len());

    let payload = "again, one more message";
    let (nnpk, _nnsk) = generate_key_pair();
    let nnbp = Basic::Ed25519.derive(nnpk);

    let seal_bundle = SealBundle::new().attach(SealData::AttachedData(payload.to_string()));

    let block3 = microledger1.pre_anchor_block(vec![nnbp], &seal_bundle);

    let signature_raw = nnsk.sign_ed(&block3.serialize()).unwrap();
    let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
    let signed_block2 = block3.to_signed_block(vec![s], &seal_bundle);
    let microledger2 = microledger1.anchor(signed_block2)?;

    assert_eq!(3, microledger2.blocks.len());
    assert_eq!(1, microledger.blocks.len());
    println!("{}", serde_json::to_string(&microledger2).unwrap());

    Ok(())
}

#[test]
fn demo_test() -> Result<(), Error> {
    let mut microledger: MicroledgerExample = MicroLedger::new();

    let example_identifiers: Vec<_> = (0..3)
        .map(|i| {
            let (pk, sk) = generate_key_pair();
            let bp = Basic::Ed25519.derive(pk);
            (i, bp, sk)
        })
        .collect();

    loop {
    let mut line = String::new();
    println!("What's your command? ");
    std::io::stdin().read_line(&mut line).unwrap();
    let data = line.trim().to_string();
    match &data[0..] {
        "APP" => {
            let mut line = String::new();
            println!("\tEnter data :");
            std::io::stdin().read_line(&mut line).unwrap();

            let data = line.trim().to_string();
            let seal_bundle = SealBundle::new().attach(SealData::AttachedData(data));

            println!("\tChoose controlling identifier:");
            example_identifiers
                .iter()
                .for_each(|(i, id, _)| println!("\t{:?}: {}", i, id.to_str()));

            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let choosed_id: usize = line.trim().parse().expect(&format!(
                "Should be number less than {}",
                example_identifiers.len()
            ));
            let (_, id, _sk) = example_identifiers[choosed_id].clone();

            let block = microledger.pre_anchor_block(vec![id], &seal_bundle);

            println!(
                "\tblock without signature: \n{}",
                serde_json::to_string_pretty(&block).unwrap()
            );

            println!("\tSign with:");
            let mut line = String::new();
            example_identifiers
                .iter()
                .for_each(|(i, id, _sk)| println!("\t{:?}: {}", i, id.to_str()));
            std::io::stdin().read_line(&mut line).unwrap();
            let choosed_id: usize = line.trim().parse().expect(&format!(
                "Should be number less than {}",
                example_identifiers.len()
            ));
            let (_i, _id, sk) = example_identifiers[choosed_id].clone();

            // Sign block, attach signature and seal provider.
            let signature_raw = sk.sign_ed(&block.serialize()).unwrap();
            let s = SelfSigning::Ed25519Sha512.derive(signature_raw);
            let signed_block = block.to_signed_block(vec![s], &seal_bundle);
            println!(
                "\tblock with signature and attachement: \n{}",
                serde_json::to_string_pretty(&signed_block).unwrap()
            );

            // Attach block to microledger.
            microledger = match microledger.anchor(signed_block) {
                Ok(m) => {
                    println!(
                        "\n---------------------\nBlock attached succesfully: {}",
                        serde_json::to_string_pretty(&m).unwrap()
                    );
                    Ok(m)
                }
                Err(e) => {
                    println!(
                        "\n------------------------\nBlock can't be added: {}",
                        e.to_string()
                    );
                    Err(e)
                }
            }?;
        }
        "MICRO" => {
            println!("{}", serde_json::to_string_pretty(&microledger).unwrap())
        }
        "HASHES" => {
            let hashes = microledger
                .blocks
                .iter()
                .map(|b| {
                    SelfAddressing::Blake3_256
                        .derive(&b.block.serialize())
                        .to_str()
                })
                .collect::<Vec<_>>()
                .join("\n");
            println!("{} <--- last block hash", hashes);
        }
        _ => todo!(),
    }
    }
    Ok(())
}
