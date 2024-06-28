use alloy_consensus::TxEnvelope;
use alloy_core::primitives::{Address, U256};
use alloy_provider::{network::Ethereum, Provider};
use alloy_sol_types::sol;
use alloy_transport::Transport;
use luban_primitives::PreconfRequest;
use LubanEscrow::LubanEscrowInstance;

use crate::base_fee_fetcher::BaseFeeFetcher;

sol! {
    #[sol(rpc)]
    contract LubanEscrow {
        #[derive(Debug)]
        function lockBlockOf(address user) public view returns (uint256);
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);
    }
}
#[derive(Debug)]
pub struct Validator<T, P, F> {
    luban_escrow_contract: LubanEscrowInstance<T, P>,
    base_fee_fetcher: F,
}

impl<T, P, F> Validator<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
    F: BaseFeeFetcher,
{
    pub fn new(provider: P, luban_escrow_contract_addr: Address, base_fee_fetcher: F) -> Self {
        let luban_escrow_contract = LubanEscrow::new(luban_escrow_contract_addr, provider);
        Self {
            luban_escrow_contract,
            base_fee_fetcher,
        }
    }

    /// validate whether the address have enough balance lockedon the escrow contract
    pub async fn validate(
        &self,
        address: &Address,
        preconf_request: &PreconfRequest,
    ) -> eyre::Result<bool> {
        let balance = self
            .luban_escrow_contract
            .balanceOf(*address)
            .call()
            .await?;
        let lock_block = self
            .luban_escrow_contract
            .lockBlockOf(*address)
            .call()
            .await?;
        if lock_block._0 != U256::MAX {
            return Ok(false);
        }

        let predict_base_fee = self.base_fee_fetcher.get_optimal_base_gas_fee().await?;
        let is_base_fee_correct = preconf_request
            .transaction()?
            .map_or(true, |tx| predict_base_fee as u128 <= get_tx_base_fee(&tx));

        Ok(
            balance._0 >= preconf_request.tip_tx.pre_pay + preconf_request.tip_tx.after_pay
                && is_base_fee_correct,
        )
    }
}

fn get_tx_base_fee(tx: &TxEnvelope) -> u128 {
    match tx {
        TxEnvelope::Legacy(t) => t.tx().gas_price,
        TxEnvelope::Eip2930(t) => t.tx().gas_price,
        TxEnvelope::Eip1559(t) => t.tx().max_fee_per_gas,
        TxEnvelope::Eip4844(t) => t.tx().tx().max_fee_per_gas,
        _ => panic!("not implemted"),
    }
}
