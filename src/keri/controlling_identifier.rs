use std::{fmt::Display, str::FromStr};

use cesrox::primitives::{
    codes::basic::Basic, parsers::parse_primitive, CesrPrimitive, IdentifierCode, PublicKey,
};
use keri::prefix::{BasicPrefix, IdentifierPrefix};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Identifier;

impl Identifier for ControllingIdentifier {}

#[derive(Clone, Debug, PartialEq)]
pub enum ControllingIdentifier {
    Keri(IdentifierPrefix),
}

impl ControllingIdentifier {
    // pub fn check_signatures(&self, msg: &[u8], signatures: &[KeriSignature]) -> Result<bool, Error> {
    //     match self {
    //         Self::Basic(id) => Ok(signatures.iter().any(|s| s.verify_with(msg, id).unwrap())),
    //     }
    // }
}

impl Display for ControllingIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControllingIdentifier::Keri(id) => write!(f, "{}", id.to_str()),
        }
    }
}

impl FromStr for ControllingIdentifier {
    type Err = keri::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_rest, (code, value)) = parse_primitive::<Basic>(s.as_bytes()).unwrap();
        let c = BasicPrefix::new(code, keri::keys::PublicKey::new(value));

        Ok(Self::Keri(IdentifierPrefix::Basic(c)))
    }
}

impl Serialize for ControllingIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ControllingIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
