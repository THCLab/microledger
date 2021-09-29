use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};

pub trait Seal {
    fn to_str(&self) -> String;
    fn derive(data: &[u8]) -> Self;
}

impl Seal for SelfAddressingPrefix {
    fn to_str(&self) -> String {
        self.to_string()
    }

    fn derive(data: &[u8]) -> Self {
        SelfAddressing::Blake3_256.derive(data)
    }
}
