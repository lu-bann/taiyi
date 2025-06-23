use alloy_primitives::{Address, U256};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::future::Future;
use taiyi_contracts::TaiyiEscrowInstance;
use taiyi_primitives::encode_util::hex_to_u64;
use thiserror::Error;
use tracing::error;

const GET_TRANSACTION_COUNT: &str = "eth_getTransactionCount";

#[derive(Debug, PartialEq)]
pub struct AccountInfo {
    pub tx_count: u64,
    pub amount: U256,
}

impl AccountInfo {
    pub const fn new(tx_count: u64, amount: U256) -> Self {
        Self { tx_count, amount }
    }

    pub fn reserve(&mut self, tx_count: u64, amount: U256) {
        self.tx_count += tx_count;
        self.amount += amount;
    }
}

impl Default for AccountInfo {
    fn default() -> Self {
        Self::new(0, U256::ZERO)
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum AccountInfoProviderError {
    #[error("reqwest error: {msg}")]
    Reqwest { msg: String },

    #[error("{0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("alloy-contract error: {msg}")]
    Contract { msg: String },
}

impl From<reqwest::Error> for AccountInfoProviderError {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest { msg: err.to_string() }
    }
}

impl From<alloy_contract::Error> for AccountInfoProviderError {
    fn from(err: alloy_contract::Error) -> Self {
        Self::Contract { msg: err.to_string() }
    }
}

pub type AccountInfoProviderResult<T> = Result<T, AccountInfoProviderError>;

#[cfg_attr(test, mockall::automock)]
pub trait AccountInfoProvider {
    fn get(&self, owner: &Address) -> impl Future<Output = AccountInfoProviderResult<AccountInfo>>;
}

#[derive(Debug)]
pub struct OnChainAccountInfoProvider {
    url: String,
    taiyi_escrow: TaiyiEscrowInstance,
}

impl OnChainAccountInfoProvider {
    pub fn new(url: String, taiyi_escrow: TaiyiEscrowInstance) -> Self {
        Self { url, taiyi_escrow }
    }
}

impl AccountInfoProvider for OnChainAccountInfoProvider {
    async fn get(&self, owner: &Address) -> AccountInfoProviderResult<AccountInfo> {
        let balance = self.taiyi_escrow.balanceOf(*owner).call().await?;
        let nonce_str = get_nonce(&self.url, &owner.to_string()).await?;
        let nonce = hex_to_u64(&nonce_str)?;
        Ok(AccountInfo::new(nonce, balance))
    }
}

#[derive(Serialize)]
struct JsonRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: serde_json::Value,
}

impl JsonRequest {
    pub fn new(method: impl Into<String>, params: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".into(), id: 1, method: method.into(), params }
    }
}

#[derive(Debug, Deserialize)]
struct JsonResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: String,
}

pub async fn get_nonce(url: &str, address: &str) -> Result<String, reqwest::Error> {
    let params = json!([address, "pending"]);
    let req = JsonRequest::new(GET_TRANSACTION_COUNT, params);
    let response: JsonResponse = Client::new().post(url).json(&req).send().await?.json().await?;
    Ok(response.result)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn account_info_reserve() {
        let mut account_info = AccountInfo::default();
        assert_eq!(account_info.tx_count, 0u64);
        assert_eq!(account_info.amount, U256::ZERO);

        let tx_count = 2;
        let amount = U256::from(13);
        account_info.reserve(tx_count, amount);

        assert_eq!(account_info.tx_count, tx_count);
        assert_eq!(account_info.amount, amount);
    }
}
