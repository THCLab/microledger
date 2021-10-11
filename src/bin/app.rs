use ::microledger::microledger::MicroLedger;
use clap::{App, Arg};
use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    keys::PublicKey,
    prefix::{BasicPrefix, Prefix, SelfSigningPrefix},
};
use microledger::{
    block::Block,
    seal_bundle::{BlockAttachment, SealBundle, SealData},
    Serialization,
};
use said::prefix::SelfAddressingPrefix;
use std::io::{self, Read};

fn main() -> Result<(), microledger::error::Error> {
    // Read microledger
    let mut serialized_microledger = String::new();
    let mut stdin = io::stdin();
    stdin.read_to_string(&mut serialized_microledger).unwrap();
    let microledger: MicroLedger<SelfAddressingPrefix, BasicPrefix, SelfSigningPrefix> =
        if serialized_microledger.len() == 0 {
            MicroLedger::new()
        } else {
            serde_json::from_str(&serialized_microledger)
                .map_err(|e| microledger::error::Error::MicroError(e.to_string()))?
        };

    // Parse arguments
    let matches = App::new("Microledger example")
        .version("1.0")
        .arg(
            Arg::new("next")
                .short('n')
                .long("next")
                .value_name("STRING")
                .about("Generate next block with given payload")
                .takes_value(false),
        )
        .arg(
            Arg::new("embeddedAttachement")
                .short('e')
                .long("embeddedAttachement")
                .takes_value(true)
                .multiple_occurrences(true)
                .value_name("STRING")
                .about("Add embedded attachement"),
        )
        .arg(
            Arg::new("controller")
                .short('c')
                .long("controller")
                .takes_value(true)
                .value_name("VEC")
                .about("Set controller identifier"),
        )
        .arg(
            Arg::new("anchor")
                .short('a')
                .long("anchor")
                .takes_value(true)
                .value_name("STRING")
                .about("Add block to microledger"),
        )
        .arg(
            Arg::new("signatures")
                .short('s')
                .long("signatures")
                .takes_value(true)
                .value_name("VEC")
                .about("Attach signature to block"),
        )
        .arg(
            Arg::new("attachment")
                .long("attachment")
                .takes_value(true)
                .value_name("STRING")
                .about("Attach seals to block"),
        )
        .get_matches();

    if matches.is_present("next") {
        // generate next block
        let public_key_raw: Vec<u8> = if let Some(c) = matches.value_of("controller") {
            serde_json::from_str(c)
                .map_err(|e| microledger::error::Error::MicroError(e.to_string()))
        } else {
            Err(microledger::error::Error::BlockError(
                "missing ids".to_string(),
            ))
        }?;
        let controlling_id = Basic::Ed25519.derive(PublicKey::new(public_key_raw));

        let seal_bundle = if let Some(i) = matches.values_of("embeddedAttachement") {
            // println!("Next block value: {:?}", i.collect::<Vec<_>>());
            i.fold(SealBundle::new(), |acc, data| {
                acc.attach(SealData::AttachedData(data.to_string()))
            })
        } else {
            SealBundle::default()
        };

        let block = microledger.pre_anchor_block(vec![controlling_id], &seal_bundle);
        println!("{:?}", serde_json::to_string(&block).unwrap());
        println!(
            "{:?}",
            serde_json::to_string(&seal_bundle.get_attachement()).unwrap()
        );
    }

    if let Some(block) = matches.value_of("anchor") {
        let block: Block<SelfAddressingPrefix, BasicPrefix> = serde_json::from_str(&block).unwrap();

        if let Some(signature) = matches.value_of("signatures") {
            let signature_raw = serde_json::from_str(signature)
                .map_err(|e| microledger::error::Error::MicroError(e.to_string()))?;
            let s = SelfSigning::Ed25519Sha512.derive(signature_raw);

            let seal_bundle = if let Some(attachement) = matches.value_of("attachement") {
                let seals: BlockAttachment = serde_json::from_str(attachement).unwrap();
                seals.to_seal_bundle()
            } else {
                SealBundle::new()
            };
            let signed_block = block.to_signed_block(vec![s], &seal_bundle);
            let m = microledger.anchor(signed_block)?;
            println!("{}", serde_json::to_string(&m).unwrap());
        } else {
        }
    }

    Ok(())
}
