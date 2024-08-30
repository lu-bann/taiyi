pub mod orderpool;
pub mod prioritized_orderpool;

use alloy_primitives::U256;
use luban_primitives::{PreconfHash, PreconfRequest};
use orderpool::{OrderPool, MAX_GAS_PER_SLOT};
use prioritized_orderpool::PrioritizedOrderPool;

use crate::{error::OrderPoolError, preconf_api::state::MAX_COMMITMENTS_PER_SLOT};

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

    pub fn slot_updated(&mut self, new_slot: u64) {
        self.orderpool.head_updated(new_slot);
        self.prioritized_orderpool.update_slot(new_slot);
    }

    pub fn prevalidate_req(
        &self,
        chain_id: u64,
        preconf_request: &PreconfRequest,
    ) -> Result<PreconfHash, OrderPoolError> {
        let preconf_hash = preconf_request.hash(U256::from(chain_id));
        if self.orderpool.exist(&preconf_hash) {
            return Err(OrderPoolError::PreconfRequestAlreadyExist(preconf_hash));
        }

        let current_slot = self
            .prioritized_orderpool
            .slot
            .ok_or(OrderPoolError::PrioritizedOrderPoolNotInitialized)?;
        if preconf_request.preconf_conditions.slot <= current_slot {
            return Err(OrderPoolError::PreconfRequestSlotTooOld(
                preconf_request.preconf_conditions.slot,
                current_slot,
            ));
        }

        // Check if we can accomodate the preconf request
        if self
            .orderpool
            .is_full(preconf_request.preconf_conditions.slot)
        {
            return Err(OrderPoolError::MaxCommitmentsReachedForSlot(
                preconf_request.preconf_conditions.slot,
                MAX_COMMITMENTS_PER_SLOT,
            ));
        }

        // Check if pool gas limit is reached
        if self
            .orderpool
            .commited_gas(preconf_request.preconf_conditions.slot)
            + preconf_request.tip_tx.gas_limit.to::<u64>()
            > MAX_GAS_PER_SLOT
        {
            return Err(OrderPoolError::MaxGasLimitReachedForSlot(
                preconf_request.preconf_conditions.slot,
                MAX_GAS_PER_SLOT,
            ));
        }

        // TODO
        // Check if the gas limit is higher than the maximum block gas limit
        // Check EIP-4844-specific limits. IMP_NOTE: if some checks fails then we call exhaust

        Ok(preconf_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::PreconfPool;
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{U256, U64};
    use alloy_rpc_client::ClientBuilder;
    use luban_primitives::{OrderingMetaData, PreconfCondition, PreconfRequest, TipTransaction};

    #[tokio::test]
    async fn test_prevalidate_req() {
        let anvil = Anvil::new().block_time(1).chain_id(1).spawn();
        let mut preconf_pool = PreconfPool::new();
        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let client = ClientBuilder::default().http(anvil.endpoint_url().into());

        let slot: U64 = client.request("eth_blockNumber", ()).await.unwrap();
        preconf_pool.slot_updated(slot.to());

        let tip_tx = TipTransaction {
            gas_limit: U256::from(1000),
            from: sender.clone(),
            to: receiver.clone(),
            pre_pay: U256::from(1),
            after_pay: U256::from(1),
            nonce: U256::from(1),
        };
        let preconf_conditions =
            PreconfCondition::new(OrderingMetaData::default(), slot.to::<u64>() + 2);
        let preconf_request = PreconfRequest {
            tip_tx,
            preconf_conditions,
            init_signature: Default::default(),
            tip_tx_signature: Default::default(),
            preconfer_signature: Default::default(),
            preconf_tx: None,
        };
        assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_ok());

        // Add the same preconf request again
        preconf_pool
            .orderpool
            .insert(preconf_request.hash(U256::from(1)), preconf_request.clone());
        assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_err());

        // Add a preconf request with slot less than current slot
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_err());
    }
}
