use std::collections::HashMap;

use taiyi_primitives::inclusion_request::InclusionRequest;

#[derive(Debug, Clone)]
pub struct Inclusion {
    pub by_slot: HashMap<u64, Vec<InclusionRequest>>,
}

impl Inclusion {
    pub fn new() -> Self {
        Self { by_slot: HashMap::new() }
    }

    pub fn get(&self, key: &u64) -> Option<Vec<InclusionRequest>> {
        self.by_slot.get(key).cloned()
    }

    pub fn contains(&self, key: &u64) -> bool {
        self.by_slot.contains_key(key)
    }

    pub fn insert(&mut self, key: u64, value: InclusionRequest) {
        self.by_slot.entry(key).or_default().push(value);
    }
}
