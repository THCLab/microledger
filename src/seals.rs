use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub trait Seal {
    fn to_str(&self) -> String;
    fn derive(data: &[u8]) -> Self;
}

#[derive(Clone, PartialEq, Debug)]
pub struct AttachmentSeal {
    sai: SelfAddressingPrefix,
}

impl AttachmentSeal {
    pub fn new(data: &[u8]) -> Self {
        Self {
            sai: SelfAddressing::Blake3_256.derive(data),
        }
    }
}

impl Serialize for AttachmentSeal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.sai.to_string())
    }
}

impl<'de> Deserialize<'de> for AttachmentSeal {
    fn deserialize<D>(deserializer: D) -> Result<AttachmentSeal, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let sai = s.parse().map_err(serde::de::Error::custom)?;

        Ok(AttachmentSeal { sai })
    }
}

impl Seal for AttachmentSeal {
    fn to_str(&self) -> String {
        self.sai.to_string()
    }

    fn derive(data: &[u8]) -> Self {
        Self {
            sai: SelfAddressing::Blake3_256.derive(data),
        }
    }
}
