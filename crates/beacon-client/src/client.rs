use std::{fmt::Debug, ops::Deref};

use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::Withdrawal;
use reqwest::Client;
use serde::{Deserialize, Serialize};

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
    endpoint: String,
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
    pub fn new(beacon_rpc_url: String, auth_token: Option<String>) -> Self {
        let inner = Client::new();
        Self { auth_token, endpoint: beacon_rpc_url, inner }
    }

    pub fn endpoint(&self) -> &String {
        &self.endpoint
    }

    /// This is a temporary solution because ethereum-consensus doesn't
    /// support the eth/v2/beacon/blocks/head endpoint yet for electra fork now.
    /// reference: https://github.com/ralexstokes/ethereum-consensus/pull/406
    pub async fn get_head_slot(&self) -> BeaconClientResult<u64> {
        let response = self.inner.get(format!("{}/eth/v2/beacon/blocks/head", self.endpoint)).send().await?;
        let result = response.bytes().await?;
        let result: BeaconBlock = serde_json::from_slice(&result)?;
        Ok(result.data.message.slot.parse::<u64>()?)
    }

    /// Fetch the previous RANDAO value from the beacon node.
    pub async fn get_prev_randao(&self) -> BeaconClientResult<B256> {
        // NOTE: The beacon_api_client crate method for this doesn't always work,
        // so we implement it manually here.

        let url = format!("{}/eth/v1/beacon/states/head/randao", self.endpoint);

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
        let url = format!("{}/eth/v1/builder/states/head/expected_withdrawals", self.endpoint);

        // Create the request builder
        let mut request_builder = self.inner.get(url.clone());

        // Add authorization header if auth_token exists
        if let Some(token) = &self.auth_token {
            request_builder = request_builder.header("Authorization", format!("Bearer {token}"));
        }

        let response = request_builder.send().await?;
        let result: GenericResponse<Vec<Withdrawal>> = response.json().await?;

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
        let url = format!("{}/eth/v1/beacon/blocks/head/root", self.endpoint);

        // Create the request builder
        let mut request_builder = self.inner.get(url.clone());

        // Add authorization header if auth_token exists
        if let Some(token) = &self.auth_token {
            request_builder = request_builder.header("Authorization", format!("Bearer {token}"));
        }

        let response = request_builder.send().await?;
        let result: GenericResponse<BlockRoot> = response.json().await?;

        Ok(B256::from_slice(result.data.root.as_slice()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockRoot {
    pub root: B256,
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + serde::de::DeserializeOwned")]
pub struct GenericResponse<T: Serialize + serde::de::DeserializeOwned> {
    pub data: T,
}

impl<T: Serialize + serde::de::DeserializeOwned> From<T> for GenericResponse<T> {
    fn from(data: T) -> Self {
        Self { data }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
#[serde(bound = "T: Serialize")]
pub struct GenericResponseRef<'a, T: Serialize> {
    pub data: &'a T,
}

impl<'a, T: Serialize> From<&'a T> for GenericResponseRef<'a, T> {
    fn from(data: &'a T) -> Self {
        Self { data }
    }
}
