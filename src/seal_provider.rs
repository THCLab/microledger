use std::collections::HashMap;

use crate::seals::Seal;
use serde::{Deserialize, Serialize};

pub trait SealProvider {
    fn check<S: Seal>(&self, s: &S) -> bool;

    fn get<S: Seal>(&self, s: &S) -> Option<String>;
}

#[derive(Serialize, Deserialize)]
pub struct DummyProvider {
    seals: HashMap<String, String>,
}

impl DummyProvider {
    pub fn new() -> Self {
        DummyProvider {
            seals: HashMap::new(),
        }
    }
}

impl SealProvider for DummyProvider {
    fn check<S: Seal>(&self, s: &S) -> bool {
        self.seals.get(&s.to_str()).is_some()
    }

    fn get<S: Seal>(&self, s: &S) -> Option<String> {
        self.seals.get(&s.to_str()).map(|s| s.to_owned())
    }
}
