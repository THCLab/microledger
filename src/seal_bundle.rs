use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    seals::{Seal, SealData},
};

pub struct SealBundle {
    pub seals: Vec<Box<dyn SealData>>,
}

impl SealBundle {
    pub fn new() -> Self {
        Self { seals: vec![] }
    }

    pub fn attach(&mut self, seal_data: Box<dyn SealData>) {
        self.seals.push(seal_data);
    }

    pub fn get_fingerprints(&self) -> Vec<Box<dyn Seal>> {
        self.seals.iter().map(|s| s.fingerprint()).collect()
    }

    pub fn get_attachement(&self) -> BlockAttachment {
        let mut hm = HashMap::new();
        let _filtered_seals = self.seals.iter().filter(|s| s.is_attached()).for_each(|s| {
            hm.insert(s.fingerprint().to_str(), s.get_data());
        });
        BlockAttachment { attachements: hm }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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
}
