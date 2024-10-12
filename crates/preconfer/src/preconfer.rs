use alloy_network::Ethereum;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_transport::Transport;
use taiyi_primitives::PreconfRequest;

use crate::{contract::TaiyiCoreInstance, error::RpcError, pricer::PreconfPricer};

#[derive(Debug, Clone)]
pub struct Preconfer<T, P, F> {
    pub taiyi_core_contract: TaiyiCoreInstance<T, P>,
    pricer: F,
}

impl<T, P, F> Preconfer<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
    F: PreconfPricer + Sync,
{
    pub fn new(provider: P, taiyi_core_contract_addr: Address, pricer: F) -> Self {
        let taiyi_core_contract = TaiyiCoreInstance::new(taiyi_core_contract_addr, provider);
        Self { taiyi_core_contract, pricer }
    }
    // TODO: take priority gas fee into account when calculating the cost
    /// validate whether the address have enough balance lockedon the escrow contract
    pub async fn verify_escrow_balance_and_calc_fee(
        &self,
        address: &Address,
        preconf_request: &PreconfRequest,
    ) -> eyre::Result<(), RpcError> {
        let balance = self.taiyi_core_contract.balanceOf(*address).call().await?;
        let lock_block = self.taiyi_core_contract.lockBlockOf(*address).call().await?;
        if lock_block._0 != U256::MAX {
            return Err(RpcError::EscrowError(
                "from address haven't deposit in escrow contract".to_string(),
            ));
        }

        let lookahead = preconf_request.target_slot().to::<u128>();
        let predict_base_fee = self.pricer.price_preconf(lookahead).await?;
        let preconf_request_tip = preconf_request.tip();

        if balance._0 < preconf_request_tip {
            return Err(RpcError::EscrowError(format!(
                "from address with {} don't have enough balance in escrow contract required {}",
                balance._0, preconf_request_tip
            )));
        }
        if U256::from(predict_base_fee) * preconf_request.tip_tx.gas_limit > preconf_request_tip {
            return Err(RpcError::EscrowError(format!(
                "preconf request tip is not enough based on predict base fee {predict_base_fee:}"
            )));
        }
        Ok(())
    }

    pub fn taiyi_core_contract_addr(&self) -> Address {
        *self.taiyi_core_contract.address()
    }
}
