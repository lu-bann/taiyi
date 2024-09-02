use alloy_network::Ethereum;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_sol_types::sol;
use alloy_transport::Transport;

use luban_primitives::PreconfRequest;
use LubanCore::LubanCoreInstance;
use LubanEscrow::LubanEscrowInstance;

use crate::{error::RpcError, pricer::PreconfPricer};

sol! {
    #[sol(rpc)]
    contract LubanEscrow {
        #[derive(Debug)]
        function lockBlockOf(address user) public view returns (uint256);
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);
    }
}

sol! {
    #[derive(Debug)]
    struct TipTx {
        uint256 gasLimit;
        address from;
        address to;
        uint256 prePay;
        uint256 afterPay;
        uint256 nonce;
    }
    #[sol(rpc)]
    contract LubanCore {
        #[derive(Debug)]
        function exhaust(TipTx calldata tipTx, bytes calldata userSignature, bytes calldata preconferSignature) external;
    }
}
#[derive(Debug, Clone)]
pub struct Preconfer<T, P, F> {
    luban_escrow_contract: LubanEscrowInstance<T, P>,
    pub luban_core_contract: LubanCoreInstance<T, P>,
    pricer: F,
}

impl<T, P, F> Preconfer<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
    F: PreconfPricer + Sync,
{
    pub fn new(
        provider: P,
        luban_escrow_contract_addr: Address,
        luban_core_contract_addr: Address,
        pricer: F,
    ) -> Self {
        let luban_escrow_contract = LubanEscrow::new(luban_escrow_contract_addr, provider.clone());
        let luban_core_contract = LubanCoreInstance::new(luban_core_contract_addr, provider);
        Self {
            luban_escrow_contract,
            luban_core_contract,
            pricer,
        }
    }
    // TODO: take priority gas fee into account when calculating the cost
    /// validate whether the address have enough balance lockedon the escrow contract
    pub async fn verify_escrow_balance_and_calc_fee(
        &self,
        address: &Address,
        preconf_request: &PreconfRequest,
    ) -> eyre::Result<bool, RpcError> {
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

        let lookahead = preconf_request.preconf_conditions.slot;
        let predict_base_fee = self.pricer.price_preconf(lookahead.into()).await?;
        let preconf_request_tip = preconf_request.tip();

        Ok(balance._0 >= preconf_request_tip
            && U256::from(predict_base_fee) * preconf_request.tip_tx.gas_limit
                <= preconf_request_tip)
    }
}
