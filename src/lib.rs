pub mod block;
pub mod controlling_identifier;
pub mod digital_fingerprint;
pub mod error;
#[cfg(feature = "keri")]
pub mod keri;
pub mod microledger;
pub mod seal_bundle;
pub mod seals;
pub mod signature;
pub mod verifier;

pub trait Encoding {}

pub trait Encode {
    fn encode(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {}
