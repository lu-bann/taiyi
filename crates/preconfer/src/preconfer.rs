use alloy_network::Ethereum;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_sol_types::sol;
use alloy_transport::Transport;
use taiyi_primitives::PreconfRequest;
use TaiyiCore::TaiyiCoreInstance;
use TaiyiEscrow::TaiyiEscrowInstance;

use crate::{error::RpcError, pricer::PreconfPricer};

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
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
    contract TaiyiCore {
        #[derive(Debug)]
        function exhaust(TipTx calldata tipTx, bytes calldata userSignature, bytes calldata preconferSignature) external;
    }
}
#[derive(Debug, Clone)]
pub struct Preconfer<T, P, F> {
    taiyi_escrow_contract: TaiyiEscrowInstance<T, P>,
    pub taiyi_core_contract: TaiyiCoreInstance<T, P>,
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
        taiyi_escrow_contract_addr: Address,
        taiyi_core_contract_addr: Address,
        pricer: F,
    ) -> Self {
        let taiyi_escrow_contract = TaiyiEscrow::new(taiyi_escrow_contract_addr, provider.clone());
        let taiyi_core_contract = TaiyiCoreInstance::new(taiyi_core_contract_addr, provider);
        Self { taiyi_escrow_contract, taiyi_core_contract, pricer }
    }
    // TODO: take priority gas fee into account when calculating the cost
    /// validate whether the address have enough balance lockedon the escrow contract
    pub async fn verify_escrow_balance_and_calc_fee(
        &self,
        address: &Address,
        preconf_request: &PreconfRequest,
    ) -> eyre::Result<(), RpcError> {
        let balance = self.taiyi_escrow_contract.balanceOf(*address).call().await?;
        let lock_block = self.taiyi_escrow_contract.lockBlockOf(*address).call().await?;
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
