use alloy_consensus::TxEnvelope;
use alloy_eips::BlockId;
use alloy_primitives::{Address, U256};
use alloy_provider::{
    ext::DebugApi,
    fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    Provider, ProviderBuilder, RootProvider,
};
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;
use alloy_sol_types::sol;
use reqwest::Url;

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

type EthClientProvider = FillProvider<
    JoinFill<
        alloy_provider::Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

#[derive(Clone, Debug)]
pub struct ExecutionClient {
    inner: EthClientProvider,
}

impl ExecutionClient {
    pub fn new(rpc_url: Url) -> Self {
        ExecutionClient { inner: ProviderBuilder::new().on_http(rpc_url) }
    }

    pub async fn get_account_state(&self, address: Address) -> eyre::Result<AccountState> {
        let nonce = self.inner.get_transaction_count(address).await?;
        let balance = self.inner.get_balance(address).await?;
        Ok(AccountState { nonce, balance })
    }

    pub async fn balance_of(
        &self,
        account: Address,
        taiyi_escrow_address: Address,
    ) -> eyre::Result<U256> {
        let taiyi_escrow = TaiyiEscrow::new(taiyi_escrow_address, self.inner.clone());
        let balance = taiyi_escrow.balanceOf(account).call().await?;
        Ok(balance._0)
    }

    pub async fn gas_used(&self, tx: TxEnvelope) -> eyre::Result<u64> {
        let trace_options = GethDebugTracingCallOptions::default();
        let trace = self
            .inner
            .debug_trace_call(tx.into(), BlockId::latest(), trace_options)
            .await?
            .try_into_default_frame()?;
        Ok(trace.gas)
    }
}

#[derive(Debug, Clone)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
}
