use std::fmt::Display;

use cesrox::{
    group::Group,
    primitives::{IdentifierCode, IndexedSignature},
};
use keri::prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix};
use sai::SelfAddressingPrefix;
use serde::{Serialize, Serializer};

use crate::error::Error;
pub trait ToCesr {
    fn to_cesr_attachment(&self) -> Result<Group, Error>;
}

// impl Verify for KeriSignature {
//     fn verify(&self, data: Vec<u8>) -> Result<(), Error> {
//         match self {
//             KeriSignature::Transferable(_, _, _, _) => todo!(),
//             KeriSignature::Nontransferable(bp, ssp) => (bp.verify(&data, ssp))
//                 .unwrap()
//                 .then(|| ())
//                 .ok_or(Error::SignatureVerificationError),
//         }
//     }
// }

impl ToCesr for KeriSignature {
    fn to_cesr_attachment(&self) -> Result<Group, Error> {
        Ok(match self {
            KeriSignature::Transferable(id, sn, digest, signatures) => {
                Group::TransIndexedSigGroups(vec![(
                    (id.clone()).into(),
                    *sn,
                    digest.into(),
                    signatures.iter().map(|sig| (sig.clone()).into()).collect(),
                )])
            }
            KeriSignature::Nontransferable(bp, ssp) => {
                Group::NontransReceiptCouples(vec![((bp.clone()).into(), (ssp.clone()).into())])
            }
        })
    }
}

pub struct KeriSignatures(pub Vec<KeriSignature>);

impl From<Group> for KeriSignatures {
    fn from(value: Group) -> Self {
        let group = match value {
            Group::NontransReceiptCouples(nontrans_sigs) => nontrans_sigs
                .into_iter()
                .filter_map(|((pk_code, pk), (sp_code, ssp))| {
                    Some(KeriSignature::Nontransferable(
                        BasicPrefix::new((pk_code).into(), keri::keys::PublicKey::new(pk.to_vec())),
                        SelfSigningPrefix::new((sp_code).into(), ssp.to_vec()),
                    ))
                })
                .collect::<Vec<_>>(),
            Group::TransIndexedSigGroups(trans_sigs) => trans_sigs
                .into_iter()
                .filter_map(|((id_code, id), sn, (dig_code, dig), sigs)| {
                    let id = match id_code {
                        IdentifierCode::Basic(bp) => IdentifierPrefix::Basic(BasicPrefix::new(
                            bp,
                            keri::keys::PublicKey::new(id),
                        )),
                        IdentifierCode::SelfAddressing(sa) => IdentifierPrefix::SelfAddressing(
                            SelfAddressingPrefix::new(sa.into(), id),
                        ),
                    };
                    Some(KeriSignature::Transferable(
                        id,
                        sn,
                        SelfAddressingPrefix::new(dig_code.into(), dig),
                        sigs,
                    ))
                })
                .collect::<Vec<_>>(),
            _ => todo!(),
        };
        KeriSignatures(group)
    }
}

/// Signatures include the cryptographic commitment of Custodians to a given Block.
#[derive(Clone, Debug, PartialEq)]
pub enum KeriSignature {
    Transferable(
        IdentifierPrefix,
        u64,
        SelfAddressingPrefix,
        Vec<IndexedSignature>,
    ),
    Nontransferable(BasicPrefix, SelfSigningPrefix),
}

impl Display for KeriSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cesr_attachment().unwrap().to_cesr_str())
    }
}

impl Serialize for KeriSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
