pub mod block;

pub trait Seals {
    fn get(&self) -> Option<String>;
}

pub trait ControlingIdentifiers {
    fn check_signatures<S: Signatures>(&self, signatures: Vec<S>) -> bool;
}

pub trait DigitalFingerprint {
    fn verify_binding(&self, data: &[u8]) -> bool;
}

pub trait Signatures {}

pub trait Encoding {}

pub trait Serialization {
    fn serialize(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {}
