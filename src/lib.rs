pub mod block;
pub mod controling_identifiers;
pub mod digital_fingerprint;
pub mod error;
pub mod microledger;
pub mod seal_bundle;
pub mod seals;
pub mod signature;

pub trait Encoding {}

pub trait Serialization {
    fn serialize(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {}
