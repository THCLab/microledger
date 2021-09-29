use keri::error::Error as KeriError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    MicroError(String),
    #[error("{0}")]
    BlockError(String),
    #[error(transparent)]
    SignatureVerificationError(#[from] KeriError),
}
