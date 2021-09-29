use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

pub trait DigitalFingerprint {
    fn derive(data: &[u8]) -> Self;
    fn verify_binding(&self, data: &[u8]) -> bool;
}

impl DigitalFingerprint for SelfAddressingPrefix {
    fn verify_binding(&self, data: &[u8]) -> bool {
        self.verify_binding(data)
    }

    fn derive(data: &[u8]) -> Self {
        SelfAddressing::Blake3_256.derive(data)
    }
}
