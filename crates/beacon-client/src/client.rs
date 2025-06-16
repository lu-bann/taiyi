use std::{fmt::Debug, ops::Deref};

use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::Withdrawal;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use lighthouse::common::eth2::GenericResponse;

/// Errors that can occur while interacting with the beacon API.
#[derive(Debug, thiserror::Error)]
pub enum BeaconClientError {
    #[error("Failed to fetch: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to decode: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Failed to parse hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Failed to parse int: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
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
    auth_token: Option<String>,
    endpoint: Url,
    inner: Client,
}

impl Deref for BeaconClient {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Serialize, Deserialize)]
struct BeaconBlock {
    version: String,
    data: BeaconBlockData,
}

#[derive(Serialize, Deserialize)]
struct BeaconBlockData {
    message: BeaconBlockMessage,
}

#[derive(Serialize, Deserialize)]
struct BeaconBlockMessage {
    slot: String,
}

impl BeaconClient {
    /// Create a new [BeaconClient] instance with the given beacon RPC URL.
    pub fn new(beacon_rpc_url: Url, auth_token: Option<String>) -> Self {
        let inner = Client::new(&beacon_rpc_url.to_string());
        Self { auth_token, endpoint: beacon_rpc_url, inner }
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// This is a temporary solution because ethereum-consensus doesn't
    /// support the eth/v2/beacon/blocks/head endpoint yet for electra fork now.
    /// reference: https://github.com/ralexstokes/ethereum-consensus/pull/406
    pub async fn get_head_slot(&self) -> BeaconClientResult<u64> {
        let response = self.inner.get("eth/v2/beacon/blocks/head").send().await?;
        let result = response.bytes().await?;
        let result: BeaconBlock = serde_json::from_slice(&result)?;
        Ok(result.data.message.slot.parse::<u64>()?)
    }

    /// Fetch the previous RANDAO value from the beacon node.
    pub async fn get_prev_randao(&self) -> BeaconClientResult<B256> {
        // NOTE: The beacon_api_client crate method for this doesn't always work,
        // so we implement it manually here.

        let url = self
            .endpoint
            .join("/eth/v1/beacon/states/head/randao")
            .map_err(|_| BeaconClientError::Url)?;

        #[derive(Deserialize)]
        struct Inner {
            randao: B256,
        }

        // Create request builder
        let mut req = self.inner.get(url);

        // Add auth header if token is present
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        // parse from /data/randao
        Ok(req.send().await?.json::<ResponseData<Inner>>().await?.data.randao)
    }

    /// Fetch the expected withdrawals for the given slot from the beacon chain.
    ///
    /// This function also maps the return type into [alloy::rpc::types::Withdrawal]s.
    pub async fn get_expected_withdrawals_at_head(&self) -> BeaconClientResult<Vec<Withdrawal>> {
        let path = format!("eth/v1/builder/states/head/expected_withdrawals");
        let url = self.endpoint.join(&path).map_err(|_| BeaconClientError::Url)?;

        // Create the request builder
        let mut request_builder = self.inner.get(url.clone());

        // Add authorization header if auth_token exists
        if let Some(token) = &self.auth_token {
            request_builder = request_builder.header("Authorization", format!("Bearer {token}"));
        }

        let response = request_builder.send().await?;
        let result: GenericResponse<Vec<Withdrawal>> = response.json().await??;

        let mut withdrawals = Vec::with_capacity(result.data.len());
        for w in result.data {
            withdrawals.push(Withdrawal {
                index: w.index,
                validator_index: w.validator_index,
                amount: w.amount,
                address: Address::from_slice(w.address.as_slice()),
            });
        }

        Ok(withdrawals)
    }

    /// Fetch the parent beacon block root from the beacon chain.
    pub async fn get_parent_beacon_block_root(&self) -> BeaconClientResult<B256> {
        let path = format!("eth/v1/beacon/blocks/head/root");
        let url = self.inner.endpoint.join(&path).map_err(|_| BeaconClientError::Url)?;

        // Create the request builder
        let mut request_builder = self.inner.get(url.clone());

        // Add authorization header if auth_token exists
        if let Some(token) = &self.auth_token {
            request_builder = request_builder.header("Authorization", format!("Bearer {token}"));
        }

        let response = request_builder.send().await?;
        let result = response.json().await??;

        Ok(B256::from_slice(result.data.root.as_slice()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseData<T> {
    pub data: T,
}

impl Debug for BeaconClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconClient").field("beacon_rpc_url", &self.endpoint).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use reqwest::Url;
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    pub struct ExtraConfig {
        pub beacon_api: Url,
    }

    pub fn get_test_config() -> eyre::Result<Option<ExtraConfig>> {
        if env::var("BEACON_API").is_err() {
            return Ok(None);
        }

        let beacon_api = env::var("BEACON_API").unwrap();

        Ok(Some(ExtraConfig { beacon_api: Url::parse(&beacon_api)? }))
    }

    #[tokio::test]
    async fn test_get_prev_randao() -> eyre::Result<()> {
        let Some(config) = get_test_config()? else {
            eprintln!("Skipping test because required environment variables are not set");
            return Ok(());
        };
        let url = config.beacon_api.clone();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return Ok(());
        }

        let beacon_api = BeaconClient::new(url, None);

        assert!(beacon_api.get_prev_randao().await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_expected_withdrawals_at_head() -> eyre::Result<()> {
        let Some(config) = get_test_config()? else {
            eprintln!("Skipping test because required environment variables are not set");
            return Ok(());
        };
        let url = config.beacon_api.clone();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return Ok(());
        }

        let beacon_api = BeaconClient::new(url, None);

        assert!(beacon_api.get_expected_withdrawals_at_head().await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_parent_beacon_block_root() -> eyre::Result<()> {
        let Some(config) = get_test_config()? else {
            eprintln!("Skipping test because required environment variables are not set");
            return Ok(());
        };
        let url = config.beacon_api.clone();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return Ok(());
        }

        let beacon_api = BeaconClient::new(url, None);

        assert!(beacon_api.get_parent_beacon_block_root().await.is_ok());
        Ok(())
    }
}
