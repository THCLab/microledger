use said::{derivation::SelfAddressing, prefix::SelfAddressingPrefix};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Error;

#[typetag::serde(tag = "type")]
pub trait Seal {
    fn to_str(&self) -> String;
    fn check(&self) -> bool;
    fn get(&self) -> Result<String, Error>;
    fn box_clone(&self) -> Box<dyn Seal>;
}

pub trait SealData {
    fn fingerprint(&self) -> Box<dyn Seal>;
    fn get_data(&self) -> String;
    fn is_attached(&self) -> bool;
}

#[derive(Clone, PartialEq, Debug)]
pub struct AttachmentSeal {
    data: Option<String>,
    sai: SelfAddressingPrefix,
}

impl SealData for AttachmentSeal {
    fn fingerprint(&self) -> Box<dyn Seal> {
        Box::new(self.get_digest())
    }

    fn get_data(&self) -> String {
        self.data.clone().unwrap()
    }

    fn is_attached(&self) -> bool {
        true
    }
}

impl AttachmentSeal {
    pub fn get_digest(&self) -> SelfAddressingPrefix {
        self.sai.clone()
    }
}

impl AttachmentSeal {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: Some(String::from_utf8(data.to_vec()).unwrap()),
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

        Ok(AttachmentSeal { data: None, sai })
    }
}

#[typetag::serde]
impl Seal for SelfAddressingPrefix {
    fn to_str(&self) -> String {
        self.to_string()
    }
    fn check(&self) -> bool {
        todo!()
    }
    fn get(&self) -> Result<String, Error> {
        todo!()
    }

    fn box_clone(&self) -> Box<dyn Seal> {
        Box::new(self.clone())
    }
}
