use cesrox::{payload::Payload, ParsedData, parse};

use crate::block::Block;
use crate::{block::SignedBlock, Encode};
use crate::microledger::Result;

use super::controlling_identifier::ControllingIdentifier;
use super::signature::{KeriSignature, KeriSignatures, ToCesr};

impl SignedBlock<ControllingIdentifier, KeriSignature> {
    pub fn to_cesr(&self) -> Result<Vec<u8>> {
        let payload = Payload::JSON(Encode::encode(&self.block));
        let att: Vec<cesrox::group::Group> = self
            .signatures
            .iter()
            .map(|a| a.to_cesr_attachment())
            .collect::<Result<_>>()
            .unwrap();
        let d = ParsedData {
            payload,
            attachments: att,
        };
        Ok(d.to_cesr().unwrap())
    }

    pub fn from_cesr(stream: &[u8]) -> Result<Self> {
        let (_rest, parsed) = parse(stream).unwrap();
        Ok(parsed.into())
    }
}

impl From<ParsedData> for SignedBlock<ControllingIdentifier, KeriSignature> {
    fn from(parsed: ParsedData) -> Self {
        let block: Block<ControllingIdentifier> = match parsed.payload {
            Payload::JSON(json) => serde_json::from_slice(&json).unwrap(),
            Payload::CBOR(_) => todo!(),
            Payload::MGPK(_) => todo!(),
        };
        let signatures: Vec<_> = parsed
            .attachments
            .into_iter()
            .map(|g| {
                let s: KeriSignatures = g.into();
                s.0
            })
            .flatten()
            .collect();
        block.to_signed_block(signatures)
    }
}
