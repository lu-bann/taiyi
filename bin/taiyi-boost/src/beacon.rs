// the code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/client/beacon.rs
use std::{fmt::Debug, ops::Deref};

use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::Withdrawal;
use beacon_api_client::{BlockId, StateId};
use reqwest::Url;
use serde::{Deserialize, Serialize};

/// Errors that can occur while interacting with the beacon API.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum BeaconClientError {
    #[error("Failed to fetch: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to decode: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Failed to parse hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Failed to parse int: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Beacon API inner error: {0}")]
    Inner(#[from] beacon_api_client::Error),
    #[error("Failed to parse or build URL")]
    Url,
}

pub type BeaconClientResult<T> = Result<T, BeaconClientError>;

/// The [BeaconApi] is responsible for fetching information from the beacon node.
///
/// Unfortunately, we cannot rely solely on [beacon_api_client::Client] because its types
/// sometimes fail to deserialize and they don't allow for custom error handling
/// which is crucial for this service.
///
/// For this reason, this struct is essentially a wrapper around [beacon_api_client::Client]
/// with added custom error handling and methods.
#[derive(Clone)]
pub struct BeaconClient {
    client: reqwest::Client,
    beacon_rpc_url: Url,

    // Inner client re-exported from the beacon_api_client crate.
    // By wrapping this, we can automatically use its existing methods
    // by dereferencing it. This allows us to extend its API.
    inner: beacon_api_client::mainnet::Client,
}

impl Deref for BeaconClient {
    type Target = beacon_api_client::mainnet::Client;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BeaconClient {
    /// Create a new [BeaconClient] instance with the given beacon RPC URL.
    pub fn new(beacon_rpc_url: Url) -> Self {
        let inner = beacon_api_client::mainnet::Client::new(beacon_rpc_url.clone());
        Self { client: reqwest::Client::new(), beacon_rpc_url, inner }
    }

    /// Fetch the previous RANDAO value from the beacon node.
    pub async fn get_prev_randao(&self) -> BeaconClientResult<B256> {
        // NOTE: The beacon_api_client crate method for this doesn't always work,
        // so we implement it manually here.

        let url = self
            .beacon_rpc_url
            .join("/eth/v1/beacon/states/head/randao")
            .map_err(|_| BeaconClientError::Url)?;

        #[derive(Deserialize)]
        struct Inner {
            randao: B256,
        }

        // parse from /data/randao
        Ok(self.client.get(url).send().await?.json::<ResponseData<Inner>>().await?.data.randao)
    }

    /// Fetch the expected withdrawals for the given slot from the beacon chain.
    ///
    /// This function also maps the return type into [alloy::rpc::types::Withdrawal]s.
    pub async fn get_expected_withdrawals_at_head(&self) -> BeaconClientResult<Vec<Withdrawal>> {
        let res = self.inner.get_expected_withdrawals(StateId::Head, None).await?;

        let mut withdrawals = Vec::with_capacity(res.len());
        for w in res {
            withdrawals.push(Withdrawal {
                index: w.index as u64,
                validator_index: w.validator_index as u64,
                amount: w.amount,
                address: Address::from_slice(w.address.as_slice()),
            });
        }

        Ok(withdrawals)
    }

    /// Fetch the parent beacon block root from the beacon chain.
    pub async fn get_parent_beacon_block_root(&self) -> BeaconClientResult<B256> {
        let res = self.inner.get_beacon_block_root(BlockId::Head).await?;
        Ok(B256::from_slice(res.as_slice()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseData<T> {
    pub data: T,
}

impl Debug for BeaconClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconClient").field("beacon_rpc_url", &self.beacon_rpc_url).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::tests::get_test_config;

    #[tokio::test]
    #[ignore = "This test needs env configs to connect to real rpcs"]
    async fn test_get_prev_randao() -> eyre::Result<()> {
        let config = get_test_config()?;
        let url = config.beacon_api.clone();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return Ok(());
        }

        let beacon_api = BeaconClient::new(url);

        assert!(beacon_api.get_prev_randao().await.is_ok());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "This test needs env configs to connect to real rpcs"]
    async fn test_get_expected_withdrawals_at_head() -> eyre::Result<()> {
        let config = get_test_config()?;
        let url = config.beacon_api.clone();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return Ok(());
        }

        let beacon_api = BeaconClient::new(url);

        assert!(beacon_api.get_expected_withdrawals_at_head().await.is_ok());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "This test needs env configs to connect to real rpcs"]
    async fn test_get_parent_beacon_block_root() -> eyre::Result<()> {
        let config = get_test_config()?;
        let url = config.beacon_api.clone();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return Ok(());
        }

        let beacon_api = BeaconClient::new(url);

        assert!(beacon_api.get_parent_beacon_block_root().await.is_ok());
        Ok(())
    }
}
