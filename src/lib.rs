pub mod block;
pub mod controlling_identifier;
pub mod digital_fingerprint;
pub mod error;
pub mod microledger;
pub mod seal_bundle;
pub mod seals;
pub mod signature;
pub mod verifier;
#[cfg(feature = "keri")]
pub mod keri;

pub trait Encoding {}

pub trait Encode {
    fn encode(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {}
