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
            .map(|g| get_signatures(g).unwrap())
            .flatten()
            .collect();
        block.to_signed_block(signatures)
    }
}
