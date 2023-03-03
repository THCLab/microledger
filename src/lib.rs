pub mod block;
pub mod digital_fingerprint;
pub mod error;
pub mod verifier;
pub mod microledger;
pub mod seal_bundle;
pub mod seals;
#[cfg(feature = "keri")]
mod keri;

pub trait Encode {
    fn encode(&self) -> Vec<u8>;
}

pub trait Identifier {}

#[cfg(test)]
mod tests {}
