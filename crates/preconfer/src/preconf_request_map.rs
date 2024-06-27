use std::{collections::HashMap, sync::Arc};

use luban_primitives::{PreconfHash, PreconfRequest};
use parking_lot::RwLock;

#[derive(Debug, Default)]
pub struct PreconfRequestMap {
    inner: Arc<RwLock<HashMap<PreconfHash, PreconfRequest>>>,
}

impl PreconfRequestMap {
    #[allow(dead_code)]
    pub fn get(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.inner.read().get(key).cloned()
    }

    pub fn exist(&self, key: &PreconfHash) -> bool {
        self.inner.read().get(key).is_some()
    }

    pub fn set(&self, key: PreconfHash, value: PreconfRequest) {
        self.inner.write().insert(key, value);
    }

    pub fn delete(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.inner.write().remove(key)
    }
}
