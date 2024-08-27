pub mod orderpool;
pub mod prioritized_orderpool;

use orderpool::OrderPool;
use prioritized_orderpool::PrioritizedOrderPool;

#[derive(Debug, Clone)]
pub struct PreconfPool {
    pub orderpool: OrderPool,
    pub prioritized_orderpool: PrioritizedOrderPool,
}

impl PreconfPool {
    pub fn new() -> Self {
        Self {
            orderpool: OrderPool::new(),
            prioritized_orderpool: PrioritizedOrderPool::default(),
        }
    }
}
