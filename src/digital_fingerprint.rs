use said::prefix::SelfAddressingPrefix;

pub trait DigitalFingerprint {
    fn verify_binding(&self, data: &[u8]) -> bool;
}

impl DigitalFingerprint for SelfAddressingPrefix {
    fn verify_binding(&self, data: &[u8]) -> bool {
        self.verify_binding(data)
    }
}
