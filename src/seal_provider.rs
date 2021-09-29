use std::collections::HashMap;

use crate::seals::Seal;

pub trait SealProvider {
    fn check<S: Seal>(&self, s: &S) -> bool;

    fn get<S: Seal>(&self, s: &S) -> Option<String>;
}

pub type Attachement = HashMap<String, String>;

impl SealProvider for Attachement {
    fn check<S: Seal>(&self, s: &S) -> bool {
        self.get(&s.to_str()).is_some()
    }

    fn get<S: Seal>(&self, s: &S) -> Option<String> {
        self.get(&s.to_str()).map(|s| s.to_owned())
    }
}
