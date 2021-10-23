use ::microledger::error::Error;
use ::microledger::microledger::MicroLedger;
use clap::{App, Arg};
use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    keys::PublicKey,
    prefix::{BasicPrefix, SelfSigningPrefix},
};
use microledger::{
    block::Block,
    seal_bundle::{BlockAttachment, SealBundle, SealData},
};
use said::prefix::SelfAddressingPrefix;
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};
use std::path::Path;

// Command line usage example:

// * help ```cat a.json | ./target/debug/app -h```

// * Create block that matches to last microledger from a.json. Sets public key
// and attachements, save block and attachements in block file
// ```cat c.json |
// ./target/debug/app next -e dsdsds -e dededeas -c "[207, 33, 70, 140, 190, 73,
// 227, 51, 134, 117, 155, 41, 226, 238, 28, 73, 46, 141, 11, 14, 220, 197, 14,
// 2, 182, 153, 185, 118, 94, 248, 41, 192]" > block```

// * attach block with signature and attachemnet to microledger `
/// ``cat c.json |
// ./target/debug/app anchor -b $(head -1 block) -s "[60, 217, 242, 58, 131, 52,
// 33, 85, 72, 98, 147, 139, 229, 124, 95, 244, 103, 118, 228, 109, 189, 8, 4,
// 237, 230, 239, 200, 201, 34, 117, 61, 123, 199, 193, 153, 39, 60, 203, 31,
// 161, 141, 3, 136, 121, 18, 57, 224, 218, 68, 107, 7, 202, 245, 0, 222, 166,
// 72, 233, 168, 190, 242, 134, 196, 6]" --attachment $(tail -1 block)```

fn main() -> Result<(), Error> {
    // Parse arguments
    let matches = App::new("Microledger example")
        .arg(
            Arg::new("serialized_microledger")
                .short('m')
                .long("serialized_microledger")
                .takes_value(true)
                .about("JSON Serialized Microledge file to work with, if file does not exist would be created"),

        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .about("Be verbose, don't use compact serialization, split on the screen information what is going on")
        )
        .version("1.0")
        .subcommand(
            App::new("create")
                .about("Create new microledger, generate genesis block")
                .arg(Arg::new("microledger_path")
                    .short('m')
                    .long("microledger_path")
                    .takes_value(true)
                    .about("Path to the file where microledger will be stored")
                )
                .arg(Arg::new("controller")
                    .short('c')
                    .long("controller")
                    .takes_value(true)
                    .multiple_values(true)
                    .about("List of controller identifiers allowed to add next block, if empty the validation strategy can be applied externally or anyone can add next block")
                )
                .arg(Arg::new("timestamp")
                    .short('t')
                    .long("timestamp")
                    .takes_value(true)
                    .about("Add authentic timestamp")
                )
                .arg(Arg::new("seal")
                    .short('s')
                    .long("seal")
                    .takes_value(true)
                    .about("Digest of the data to be anchored on the block")
                )
        )
        .subcommand(
            App::new("next")
                .about("Generate next block with given payload and controlling identifiers")
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
                        .about("Set controlling identifier"),
                ),
        )
        .subcommand(
            App::new("anchor")
                .about("Add block to microledger")
                .arg(
                    Arg::new("block")
                        .short('b')
                        .long("anchor")
                        .takes_value(true)
                        .value_name("BLOCK")
                        .about("Block to be added"),
                )
                .arg(
                    Arg::new("signatures")
                        .short('s')
                        .long("signatures")
                        .takes_value(true)
                        .value_name("SIGNATURE")
                        .about("Attach signature to block"),
                )
                .arg(
                    Arg::new("attachment")
                        .long("attachment")
                        .takes_value(true)
                        .value_name("STRING")
                        .about("Attach seals to block"),
                ),
        )
        .get_matches();

    let verbose = matches.is_present("verbose");

    // Create new microledger
    if let Some(ref matches) = matches.subcommand_matches("create") {
        let microledger_file_path = matches.value_of("microledger_path").unwrap();
        let mut file =
            File::create(microledger_file_path).expect("Can't create a microledger file");
        let microledger: MicroLedger<SelfAddressingPrefix, BasicPrefix, SelfSigningPrefix> =
            MicroLedger::new();

        let controlling_ids: BasicPrefix = if let Some(c) = matches.value_of("controller") {
            Ok(c.parse()?)
        } else {
            Err(microledger::error::Error::BlockError(
                "missing ids".to_string(),
            ))
        }?;

        let seal_bundle = if let Some(i) = matches.values_of("embeddedAttachement") {
            i.fold(SealBundle::new(), |acc, data| {
                acc.attach(SealData::AttachedData(data.to_string()))
            })
        } else {
            SealBundle::default()
        };

        let block = microledger.pre_anchor_block(vec![controlling_ids], &seal_bundle);
        println!("{}", serde_json::to_string(&block).unwrap());
        println!(
            "{}",
            serde_json::to_string(&seal_bundle.get_attachement()).unwrap()
        );
        let serialized_block = serde_json::to_string(&block).unwrap();
        file.write_all(serialized_block.as_bytes());
    }

    //    let microledger: MicroLedger<SelfAddressingPrefix, BasicPrefix, SelfSigningPrefix> =
    //                serde_json::from_str(&serialized_microledger).unwrap_or(MicroLedger::new())

    //    if let Some(ref matches) = matches.subcommand_matches("next") {
    //        // generate next block
    //        let controlling_id: BasicPrefix = if let Some(c) = matches.value_of("controller") {
    //            Ok(c.parse()?)
    //        } else {
    //            Err(microledger::error::Error::BlockError(
    //                "missing ids".to_string(),
    //            ))
    //        }?;
    //
    //        let seal_bundle = if let Some(i) = matches.values_of("embeddedAttachement") {
    //            i.fold(SealBundle::new(), |acc, data| {
    //                acc.attach(SealData::AttachedData(data.to_string()))
    //            })
    //        } else {
    //            SealBundle::default()
    //        };
    //
    //        let block = microledger.pre_anchor_block(vec![controlling_id], &seal_bundle);
    //        println!("{}", serde_json::to_string(&block).unwrap());
    //        println!(
    //            "{}",
    //            serde_json::to_string(&seal_bundle.get_attachement()).unwrap()
    //        );
    //    }
    //
    //    if let Some(ref matches) = matches.subcommand_matches("anchor") {
    //        let block = matches
    //            .value_of("block")
    //            .ok_or(Error::MicroError("Missing block argument".into()))?;
    //        let block: Block<SelfAddressingPrefix, BasicPrefix> = serde_json::from_str(&block).unwrap();
    //
    //        if let Some(signature) = matches.value_of("signatures") {
    //            let s: SelfSigningPrefix = signature.parse()?;
    //
    //            let seal_bundle = if let Some(attachment) = matches.value_of("attachment") {
    //                let seals: BlockAttachment = serde_json::from_str(attachment)
    //                    .map_err(|e| Error::MicroError(e.to_string()))?;
    //                seals.to_seal_bundle()
    //            } else {
    //                SealBundle::new()
    //            };
    //            let signed_block = block.to_signed_block(vec![s], &seal_bundle);
    //            let m = microledger.anchor(signed_block)?;
    //            println!("{}", serde_json::to_string(&m).unwrap());
    //        } else {
    //            // missing signatures
    //        }
    //    }

    Ok(())
}
