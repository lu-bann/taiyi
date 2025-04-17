/// The code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/client/execution.rs
use std::ops::{Deref, DerefMut};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, Bytes, TxHash, B256, U256, U64};
use alloy_provider::{
    fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    ProviderBuilder, RootProvider,
};
use alloy_rpc_client::{BatchRequest, ClientBuilder, RpcClient};
use alloy_rpc_types_eth::{Block, FeeHistory, TransactionReceipt};
use alloy_transport::{TransportErrorKind, TransportResult};
use futures::{stream::FuturesUnordered, StreamExt};
use reqwest::Url;

use crate::types::AccountState;

type EthClientProvider = FillProvider<
    JoinFill<
        alloy_provider::Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;
/// An HTTP-based JSON-RPC execution client provider that supports batching.
///
/// This struct is a wrapper over an inner [`RootProvider`] and extends it with
/// methods that are relevant to the Bolt state.
#[derive(Clone, Debug)]
pub struct ExecutionClient {
    /// The custom RPC client that allows us to add custom batching and extend the provider.
    rpc: RpcClient,
    /// The inner provider that implements all the JSON-RPC methods, that can be
    /// easily used via dereferencing this struct.
    inner: EthClientProvider,
}

impl Deref for ExecutionClient {
    type Target = FillProvider<
        JoinFill<
            alloy_provider::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        RootProvider,
    >;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ExecutionClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[allow(dead_code)]
impl ExecutionClient {
    /// Create a new `RpcClient` with the given URL.
    pub fn new<U: Into<Url>>(url: U) -> Self {
        let url = url.into();
        let rpc = ClientBuilder::default().http(url.clone());
        let inner = ProviderBuilder::new().on_http(url);

        Self { rpc, inner }
    }

    /// Create a new batch request.
    pub fn new_batch(&self) -> BatchRequest<'_> {
        self.rpc.new_batch()
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> TransportResult<u64> {
        let chain_id: String = self.rpc.request("eth_chainId", ()).await?;
        let chain_id = chain_id
            .get(2..)
            .ok_or(TransportErrorKind::Custom("not hex prefixed result".into()))?;

        let decoded = u64::from_str_radix(chain_id, 16).map_err(|e| {
            TransportErrorKind::Custom(format!("could not decode {chain_id} into u64: {e}").into())
        })?;
        Ok(decoded)
    }

    /// Get the basefee of the latest block.
    pub async fn get_basefee(&self, block_number: Option<u64>) -> TransportResult<u128> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let fee_history: FeeHistory =
            self.rpc.request("eth_feeHistory", (U64::from(1), tag, &[] as &[f64])).await?;

        let Some(base_fee) = fee_history.latest_block_base_fee() else {
            return Err(TransportErrorKind::Custom("Base fee not found".into()).into());
        };

        Ok(base_fee)
    }

    /// Get the blob basefee of the latest block.
    ///
    /// Reference: https://github.com/ethereum/execution-apis/blob/main/src/eth/fee_market.yaml
    pub async fn get_blob_basefee(&self, block_number: Option<u64>) -> TransportResult<u128> {
        let block_count = U64::from(1);
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);
        let reward_percentiles: Vec<f64> = vec![];
        let fee_history: FeeHistory =
            self.rpc.request("eth_feeHistory", (block_count, tag, &reward_percentiles)).await?;

        Ok(fee_history.latest_block_blob_base_fee().unwrap_or(0))
    }

    /// Get the latest block number
    pub async fn get_head(&self) -> TransportResult<u64> {
        let result: U64 = self.rpc.request("eth_blockNumber", ()).await?;

        Ok(result.to())
    }

    /// Gets the latest account state for the given address
    pub async fn get_account_state(
        &self,
        address: &Address,
        block_number: Option<u64>,
    ) -> TransportResult<AccountState> {
        let mut batch = self.rpc.new_batch();

        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let balance =
            batch.add_call("eth_getBalance", &(address, tag)).expect("Correct parameters");

        let tx_count =
            batch.add_call("eth_getTransactionCount", &(address, tag)).expect("Correct parameters");

        let code = batch.add_call("eth_getCode", &(address, tag)).expect("Correct parameters");

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        let tx_count: U64 = tx_count.await?;
        let balance: U256 = balance.await?;
        let code: Bytes = code.await?;

        Ok(AccountState { balance, transaction_count: tx_count.to(), has_code: !code.is_empty() })
    }

    /// Get the block with the given number. If `None`, the latest block is returned.
    pub async fn get_block(&self, block_number: Option<u64>, full: bool) -> TransportResult<Block> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        self.rpc.request("eth_getBlockByNumber", (tag, full)).await
    }

    /// Send a raw transaction to the network.
    pub async fn send_raw_transaction(&self, raw: Bytes) -> TransportResult<B256> {
        self.rpc.request("eth_sendRawTransaction", [raw]).await
    }

    /// Get the receipts for a list of transaction hashes.
    pub async fn get_receipts(
        &self,
        hashes: &[TxHash],
    ) -> TransportResult<Vec<Option<TransactionReceipt>>> {
        let mut batch = self.rpc.new_batch();

        let futs = FuturesUnordered::new();

        for hash in hashes {
            futs.push(
                batch
                    .add_call("eth_getTransactionReceipt", &(&[hash]))
                    .expect("Correct parameters"),
            );
        }

        batch.send().await?;

        Ok(futs
            .collect::<Vec<TransportResult<TransactionReceipt>>>()
            .await
            .into_iter()
            .map(|r| r.ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_consensus::constants::ETH_TO_WEI;
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{uint, Uint};

    use super::*;
    use crate::utils::tests::get_test_config;

    #[tokio::test]
    async fn test_rpc_client() {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let anvil_url = Url::from_str(&anvil.endpoint()).unwrap();
        let client = ExecutionClient::new(anvil_url);

        let addr = anvil.addresses().first().unwrap();

        let account_state = client.get_account_state(addr, None).await.unwrap();

        // Accounts in Anvil start with 10_000 ETH
        assert_eq!(account_state.balance, uint!(10_000U256 * Uint::from(ETH_TO_WEI)));

        assert_eq!(account_state.transaction_count, 0);
    }

    #[tokio::test]
    async fn test_get_receipts() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt().try_init();
        let Some(config) = get_test_config()? else {
            eprintln!("Skipping test because required environment variables are not set");
            return Ok(());
        };
        let client = ExecutionClient::new(config.execution_api.clone());

        let _receipts = client
            .get_receipts(&[
                TxHash::from_str(
                    "0xc0e4c278eb6e90c285cbe7dd28c5da4282d819b38667da353922f8ef5e7a2eec",
                )
                .unwrap(),
                TxHash::from_str(
                    "0x5a22423048cd9bd76eee03a1deae0527d74850a2f0af179b363cde25309b275f",
                )
                .unwrap(),
                TxHash::from_str(
                    "0x467602dac55190551fd9a143ca8c8e45e6892c86c9e9703c21aac4f30484b80f",
                )
                .unwrap(),
            ])
            .await
            .unwrap();

        println!("{_receipts:?}");
        Ok(())
    }
}
