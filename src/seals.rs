use said::prefix::SelfAddressingPrefix;

pub trait Seal {
    fn to_str(&self) -> String;
}

impl Seal for SelfAddressingPrefix {
    fn to_str(&self) -> String {
        self.to_string()
    }
}
