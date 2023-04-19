pub(crate) mod helpers {
    use base64::{engine::general_purpose, Engine};
    use ed25519_dalek::{PublicKey, Signature as EdLibSignature, Verifier as EdLibVerifier};
    use serde::{Deserialize, Serialize};

    use microledger::{verifier::Verifier, Identifier, Result, Signature};

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct EasyIdentifier(pub String);

    impl Identifier for EasyIdentifier {}

    #[derive(Serialize, Deserialize, Clone)]
    pub struct EdSignature(pub String);
    impl Signature for EdSignature {
        type Identifier = EasyIdentifier;

        fn get_signer(&self) -> Option<Self::Identifier> {
            Some(EasyIdentifier("Identifier1".into()))
        }
    }
    pub struct EdVerifier(pub PublicKey);

    impl Verifier for EdVerifier {
        type Signature = EdSignature;

        fn verify(&self, data: &[u8], s: Vec<Self::Signature>) -> Result<bool> {
            Ok(s.iter().all(|sig| {
                let raw_sig = general_purpose::STANDARD_NO_PAD.decode(&sig.0).unwrap();
                self.0
                    .verify(data, &EdLibSignature::from_bytes(&raw_sig).unwrap())
                    .is_ok()
            }))
        }
    }
}
#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use base64::{engine::general_purpose, Engine};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;
    use said::derivation::{HashFunctionCode, HashFunction};

    use microledger::{
        block::Block,
        digital_fingerprint::DigitalFingerprint,
        error::Error,
        microledger::{MicroLedger, MicroledgerError},
        seal_bundle::{SealBundle, SealData},
        seals::Seal,
        Encode, Result,
    };

    use crate::helpers::{EasyIdentifier, EdSignature, EdVerifier};

    #[test]
    fn test_block_serialization() -> Result<()> {
        // generate keypair
        let id = EasyIdentifier("Identifier1".to_string());

        let seal = HashFunction::from(HashFunctionCode::Blake3_256).derive("exmaple".as_bytes());
        let prev = Some(DigitalFingerprint::SelfAddressing(
            HashFunction::from(HashFunctionCode::Blake3_256).derive("exmaple".as_bytes()),
        ));
        let block = Block::new(vec![Seal::Attached(seal)], prev, vec![(id)]);
        println!("{}", String::from_utf8(block.encode()?).unwrap());

        let deserialized_block: Block<EasyIdentifier> =
            serde_json::from_slice(&block.encode()?).unwrap();
        assert_eq!(block.encode()?, deserialized_block.encode()?);
        Ok(())
    }

    #[test]
    fn test_microledger() -> Result<()> {
        // generate keypair and setup verifier
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let pk = kp.public;
        let validator = Arc::new(EdVerifier(pk));

        let identifier = EasyIdentifier("Identifier1".to_string());

        let mut microledger = MicroLedger::new(validator);
        let seals = SealBundle::new().attach(SealData::AttachedData("hello".into()));
        let block = microledger.pre_anchor_block(vec![identifier.clone()], &seals)?;

        let sign = |data: Vec<u8>| kp.sign(&data).as_ref().to_vec();

        let b64_signature =
            general_purpose::STANDARD_NO_PAD.encode(sign(b"Wrong signature".to_vec()));

        let signed = block
            .clone()
            .to_signed_block(vec![EdSignature(b64_signature)]);
        assert!(matches!(
            microledger.anchor(signed),
            Err(Error::MicroError(MicroledgerError::WrongBlock))
        ));

        assert!(microledger.blocks.is_empty());

        // Construct block without controlling identifier
        let block_no_controllers = microledger.pre_anchor_block(vec![], &seals)?;

        let b64_signature =
            general_purpose::STANDARD_NO_PAD.encode(sign(block_no_controllers.encode()?));

        let signed = block_no_controllers.to_signed_block(vec![EdSignature(b64_signature)]);
        assert!(matches!(
            microledger.anchor(signed),
            Err(Error::MicroError(MicroledgerError::WrongSigner))
        ));
        assert!(microledger.blocks.is_empty());

        let b64_signature = general_purpose::STANDARD_NO_PAD.encode(sign(block.encode()?));
        let signed = block.to_signed_block(vec![EdSignature(b64_signature)]);

        microledger.anchor(signed)?;
        assert_eq!(microledger.blocks.len(), 1);

        let seals = SealBundle::new().attach(SealData::AttachedData("hello2".into()));
        let block = microledger.pre_anchor_block(vec![(identifier.clone())], &seals)?;

        let b64_signature = general_purpose::STANDARD_NO_PAD.encode(sign(block.encode()?));

        let signed = block.to_signed_block(vec![EdSignature(b64_signature)]);
        microledger.anchor(signed)?;
        assert_eq!(microledger.blocks.len(), 2);

        let blocks = microledger.blocks;
        println!("{}", serde_json::to_string(&blocks).unwrap());

        Ok(())
    }
}
