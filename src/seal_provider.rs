use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::seals::Seal;

pub trait SealProvider {
    fn check<S: Seal>(&self, s: &S) -> bool;

    fn get<S: Seal>(&self, s: &S) -> Option<String>;
}

#[derive(Serialize, Clone, Deserialize, Default, PartialEq, Debug)]
pub struct SealsAttachement {
    seals: HashMap<String, String>,
}

impl SealProvider for SealsAttachement {
    fn check<S: Seal>(&self, s: &S) -> bool {
        self.seals.get(&s.to_str()).is_some()
    }

    fn get<S: Seal>(&self, s: &S) -> Option<String> {
        self.seals.get(&s.to_str()).map(|s| s.to_owned())
    }
}

impl SealsAttachement {
    pub fn new() -> Self {
        SealsAttachement {
            seals: HashMap::new(),
        }
    }

    /// Saves data in attachement and return hash used as a key.
    pub fn save<S: Seal>(&mut self, data: &[u8]) -> Option<S> {
        let seal = S::derive(data);
        self.seals
            .insert(seal.to_str(), String::from_utf8(data.to_vec()).unwrap());
        Some(seal)
    }
}
