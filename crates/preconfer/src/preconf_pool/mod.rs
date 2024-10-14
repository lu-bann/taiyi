pub mod orderpool;
pub mod prioritized_orderpool;

use alloy_primitives::U256;
use orderpool::{OrderPool, MAX_GAS_PER_SLOT};
use prioritized_orderpool::PrioritizedOrderPool;
use taiyi_primitives::{PreconfHash, PreconfRequest};

use crate::{error::OrderPoolError, preconf_api::state::MAX_COMMITMENTS_PER_SLOT};

#[derive(Debug, Clone)]
pub struct PreconfPool {
    pub orderpool: OrderPool,
    pub prioritized_orderpool: PrioritizedOrderPool,
}

impl PreconfPool {
    pub fn new() -> Self {
        Self { orderpool: OrderPool::new(), prioritized_orderpool: PrioritizedOrderPool::default() }
    }

    pub fn slot_updated(&mut self, new_slot: u64) {
        self.orderpool.head_updated(new_slot);
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
        let target_slot = preconf_request.target_slot().to();

        // Check if we can accomodate the preconf request
        if self.orderpool.is_full(target_slot) {
            return Err(OrderPoolError::MaxCommitmentsReachedForSlot(
                target_slot,
                MAX_COMMITMENTS_PER_SLOT,
            ));
        }

        // Check if pool gas limit is reached
        if self.orderpool.commited_gas(target_slot) + preconf_request.tip_tx.gas_limit.to::<u64>()
            > MAX_GAS_PER_SLOT
        {
            return Err(OrderPoolError::MaxGasLimitReachedForSlot(target_slot, MAX_GAS_PER_SLOT));
        }

        // TODO
        // Check if the gas limit is higher than the maximum block gas limit
        // Check EIP-4844-specific limits. IMP_NOTE: if some checks fails then we call exhaust

        Ok(preconf_hash)
    }
}

#[cfg(test)]
mod tests {
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{keccak256, U256, U64};
    use alloy_rpc_client::ClientBuilder;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use taiyi_primitives::{PreconfRequest, TipTransaction};

    use super::PreconfPool;

    // FIXME
    #[tokio::test]
    #[ignore]
    async fn test_prevalidate_req() {
        let anvil = Anvil::new().block_time(1).chain_id(1).spawn();
        let mut preconf_pool = PreconfPool::new();
        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let client = ClientBuilder::default().http(anvil.endpoint_url().into());

        let slot: U64 = client.request("eth_blockNumber", ()).await.unwrap();
        preconf_pool.slot_updated(slot.to());

        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();

        let tip_tx = TipTransaction {
            gas_limit: U256::from(1000),
            from: sender.clone(),
            to: receiver.clone(),
            pre_pay: U256::from(1),
            after_pay: U256::from(1),
            nonce: U256::from(1),
            target_slot: U256::from(slot.to::<u64>() + 2),
        };
        let tip_tx_signature = signer
            .sign_hash(&keccak256(&tip_tx.tip_tx_hash(U256::from(anvil.chain_id()))))
            .await
            .unwrap();

        let preconf_request = PreconfRequest {
            tip_tx,
            tip_tx_signature,
            preconfer_signature: None,
            preconf_tx: None,
            preconf_req_signature: None,
        };
        assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_ok());

        // Add the same preconf request again
        preconf_pool.orderpool.insert(preconf_request.hash(U256::from(1)), preconf_request.clone());
        assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_err());

        // Add a preconf request with slot less than current slot
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_err());
    }
}
