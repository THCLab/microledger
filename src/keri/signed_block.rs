use cesrox::{parse, payload::Payload, ParsedData};
use keri::event_message::signature::{get_signatures, signatures_into_groups};
use keri::prefix::IdentifierPrefix;

use crate::block::Block;
use crate::microledger::Result;
use crate::{block::SignedBlock, Encode};

use super::KeriSignature;

impl SignedBlock<IdentifierPrefix, KeriSignature> {
    pub fn to_cesr(&self) -> Result<Vec<u8>> {
        let payload = Payload::JSON(Encode::encode(&self.block));
        let groups = signatures_into_groups(&self.signatures);

        let d = ParsedData {
            payload,
            attachments: groups,
        };
        Ok(d.to_cesr().unwrap())
    }

    pub fn from_cesr(stream: &[u8]) -> Result<Self> {
        let (_rest, parsed) = parse(stream).unwrap();
        Ok(parsed.into())
    }
}

impl From<ParsedData> for SignedBlock<IdentifierPrefix, KeriSignature> {
    fn from(parsed: ParsedData) -> Self {
        let block: Block<IdentifierPrefix> = match parsed.payload {
            Payload::JSON(json) => serde_json::from_slice(&json).unwrap(),
            Payload::CBOR(_) => todo!(),
            Payload::MGPK(_) => todo!(),
        };
        let signatures: Vec<_> = parsed
            .attachments
            .into_iter()
            .flat_map(|g| get_signatures(g).unwrap())
            .collect();
        block.to_signed_block(signatures)
    }
}

#[cfg(test)]
mod test {
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
    use sai::derivation::SelfAddressing;
    use tempfile::Builder;

    use crate::{
        block::{Block, SignedBlock},
        digital_fingerprint::DigitalFingerprint,
        keri::KeriSignature,
        seals::Seal,
        Encode,
    };

    #[test]
    fn test_signed_block() {
        use crate::keri::verifier::KeriVerifier;
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let _event_processor = BasicProcessor::new(Arc::clone(&db), None);
        let validator = Arc::new(KeriVerifier::new(db));

        // generate keypair
        let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
        let (pk, sk) = (kp.public, kp.secret);
        let pref = BasicPrefix::Ed25519(PublicKey::new(pk.as_bytes().to_vec()));
        let bp = keri::prefix::IdentifierPrefix::Basic(pref.clone());

        let sign = |data| {
            ExpandedSecretKey::from(&sk)
                .sign(data, &pk)
                .as_ref()
                .to_vec()
        };
        let seal = SelfAddressing::Blake3_256.derive("exmaple".as_bytes());
        let prev = Some(DigitalFingerprint::SelfAddressing(
            SelfAddressing::Blake3_256.derive("exmaple".as_bytes()),
        ));
        let block = Block::new(vec![Seal::Attached(seal)], prev, vec![(bp)]);

        let sig = KeriSignature::NonTransferable(Nontransferable::Couplet(vec![(
            pref,
            SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, sign(&block.encode())),
        )]));

        let signed = block.to_signed_block(vec![sig]);
        assert!(signed.verify(validator, None).unwrap());

        let signed_block_cesr = signed.to_cesr().unwrap();

        let block_from_cesr =
            SignedBlock::<IdentifierPrefix, KeriSignature>::from_cesr(&signed_block_cesr).unwrap();
        assert_eq!(block_from_cesr.block, signed.block);
        assert_eq!(block_from_cesr.signatures, signed.signatures);
    }
}
