pub mod block;

pub trait Seal {}

pub trait SealProvider {
    fn check<S: Seal>(&self, s: &S) -> bool;

    fn get(&self) -> Option<String>;
}

pub trait ControlingIdentifier {
    fn check_signatures<S: Signature>(&self, signatures: Vec<S>) -> bool;
}

pub trait DigitalFingerprint {
    fn verify_binding(&self, data: &[u8]) -> bool;
}

pub trait Signature {}

pub trait Encoding {}

pub trait Serialization {
    fn serialize(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {}
