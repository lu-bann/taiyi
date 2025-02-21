use alloy_eips::BlockId;
use alloy_primitives::{Address, U256};
use alloy_provider::{ext::DebugApi, Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;
use alloy_sol_types::sol;
use alloy_transport_http::Http;
use reqwest::{Client, Url};

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionClient {
    inner: RootProvider<Http<Client>>,
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

    pub async fn gas_used(&self, tx: TransactionRequest) -> eyre::Result<u64> {
        let trace_options = GethDebugTracingCallOptions::default();
        let trace = self
            .inner
            .debug_trace_call(tx, BlockId::latest(), trace_options)
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use alloy_network::TransactionBuilder;
    use alloy_primitives::{Address, U256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;

    use crate::clients::execution_client::ExecutionClient;

    #[tokio::test]
    async fn test_gas_used() -> eyre::Result<()> {
        let anvil = alloy_node_bindings::Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();
        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let client = ExecutionClient::new(rpc_url.parse().unwrap());

        let tx = TransactionRequest::default()
            .with_from(*sender)
            .with_to(*receiver)
            .with_value(U256::from(100))
            .with_nonce(0)
            .with_max_fee_per_gas(1)
            .with_max_priority_fee_per_gas(1);

        let gas_used = client.gas_used(tx).await?;
        assert_eq!(gas_used, 21000);
        Ok(())
    }
}
