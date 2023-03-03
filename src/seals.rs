use std::str::FromStr;

use sai::SelfAddressingPrefix;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum Seal {
    Attached(SelfAddressingPrefix),
}

impl Seal {
    pub fn fingerprint(&self) -> String {
        match self {
            Seal::Attached(sai) => sai.to_string(),
        }
    }
    pub fn to_str(&self) -> String {
        match self {
            Seal::Attached(sai) => ["A", &sai.to_string()].join(""),
        }
    }
}

impl FromStr for Seal {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Seal::Attached(s[1..].parse().map_err(|_e| {
                Error::SealError("Can't parse self adressing prefix".into())
            })?)),
            _ => Err(Error::SealError("Improper seal prefix".into())),
        }
    }
}

impl Serialize for Seal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

impl<'de> Deserialize<'de> for Seal {
    fn deserialize<D>(deserializer: D) -> Result<Seal, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Seal::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[test]
pub fn test_parse_seal() {
    let seal_str = "AEPq_TXbqQFKrIZn9Sw8CGDMVqcDF4eipFgHr__lhcics";
    let seal: Result<Seal, _> = Seal::from_str(seal_str);
    assert!(seal.is_ok());
}
