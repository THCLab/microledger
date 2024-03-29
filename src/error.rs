#[cfg(feature = "keri")]
use keri::prefix::error::Error as PrefixError;
use thiserror::Error;

use crate::{block::BlockError, microledger::MicroledgerError};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    MicroError(#[from] MicroledgerError),

    #[error("{0}")]
    BlockError(#[from] BlockError),

    #[error("{0}")]
    SealError(String),

    #[error("Signature verification error")]
    SignatureVerificationError,

    #[error("Can't encode element")]
    EncodeError(#[from] serde_json::Error),

    #[cfg(feature = "keri")]
    #[error(transparent)]
    BasicPrefixError(#[from] PrefixError),

    #[error("Can't parse cesr stream")]
    CesrError,

    #[error("Missing fingerprint")]
    MissingFingerprintError,
}
