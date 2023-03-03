#[cfg(feature = "keri")]
use keri::prefix::error::Error as PrefixError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    MicroError(String),
    #[error("{0}")]
    BlockError(String),
    #[error("{0}")]
    SealError(String),
    #[error("Signature verification error")]
    SignatureVerificationError,
    #[cfg(feature = "keri")]
    #[error(transparent)]
    BasicPrefixError(#[from] PrefixError),
}
