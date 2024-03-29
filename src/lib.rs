use error::Error;

pub mod block;
pub mod error;
#[cfg(feature = "keriox")]
pub mod keri;
pub mod microledger;
pub mod seal_bundle;
pub mod seals;
pub mod verifier;

pub type Result<T> = std::result::Result<T, Error>;

pub trait Encode {
    fn encode(&self) -> Result<Vec<u8>>;
}

/// Controlling identifier describes control authority over the Microledger in a given block.
/// Control _MAY_ be established for single or multiple identifiers through the multisig feature.
/// Controlling identifiers can be anything that is considered identifiable within given network,
/// ie. `Public Key`, `DID`, `KERI` prefix and so on.
pub trait Identifier {}
pub trait Signature {
    type Identifier;
    fn get_signer(&self) -> Option<Self::Identifier>;
}
