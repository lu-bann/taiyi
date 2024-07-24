use luban_primitives::PreconfRequest;
use std::{collections::HashMap, time::Instant};

/// OrderPool is a struct that holds the preconf requests and the time they were added to the pool.
#[derive(Debug)]
pub struct OrderPool {
    preconf_reqs: HashMap<PreconfRequest, Instant>,
}

impl OrderPool {
    /// Creates a new OrderPool.
    pub fn new() -> Self {
        Self {
            preconf_reqs: HashMap::new(),
        }
    }

    /// Adds a preconf request to the pool.
    pub fn add_preconf_request(&mut self, preconf_req: PreconfRequest) {
        todo!()
    }

    /// Removes a preconf request from the pool.
    pub fn remove_preconf_request(&mut self, preconf_req: PreconfRequest) {
        todo!()
    }

    /// Returns the number of preconf requests in the pool.
    pub fn len(&self) -> usize {
        self.preconf_reqs.len()
    }
}
