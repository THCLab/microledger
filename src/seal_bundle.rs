use sai::derivation::SelfAddressing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::seals::Seal;

#[derive(Clone)]
pub enum SealData {
    AttachedData(String),
}

impl SealData {
    pub fn fingerprint(&self) -> Seal {
        match self {
            SealData::AttachedData(data) => {
                Seal::Attached(SelfAddressing::Blake3_256.derive(data.as_bytes()))
            }
        }
    }
}

#[derive(Default)]
pub struct SealBundle {
    pub seals: Vec<SealData>,
}

impl SealBundle {
    pub fn new() -> Self {
        Self { seals: vec![] }
    }

    pub fn attach(&self, seal_data: SealData) -> Self {
        let mut seals = self.seals.clone();
        seals.push(seal_data);
        Self { seals }
    }

    pub fn get_fingerprints(&self) -> Vec<Seal> {
        self.seals.iter().map(|s| s.fingerprint()).collect()
    }

    pub fn get_attachement(&self) -> BlockAttachment {
        let mut hm = HashMap::new();
        self.seals.iter().for_each(|s| match s {
            SealData::AttachedData(data) => {
                hm.insert(s.fingerprint().fingerprint(), data.to_string());
            }
        });
        BlockAttachment { attachements: hm }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct BlockAttachment {
    attachements: HashMap<String, String>,
}

impl BlockAttachment {
    pub fn new() -> Self {
        Self {
            attachements: HashMap::new(),
        }
    }

    pub fn get(&self, digest: &str) -> Option<String> {
        self.attachements.get(digest).map(|s| s.to_string())
    }

    pub fn to_seal_bundle(&self) -> SealBundle {
        self.attachements.iter().fold(SealBundle::new(), |acc, v| {
            acc.attach(SealData::AttachedData(v.1.clone()))
        })
    }
}
