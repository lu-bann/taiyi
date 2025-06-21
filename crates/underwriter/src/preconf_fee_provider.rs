use std::future::Future;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use taiyi_primitives::PreconfFee;

#[cfg_attr(test, mockall::automock)]
pub trait PreconfFeeProvider {
    fn get(&self, slot: u64) -> impl Future<Output = Result<PreconfFee, reqwest::Error>>;
}

#[derive(Debug)]
pub struct TaiyiPreconfFeeProvider {
    url: String,
}

impl TaiyiPreconfFeeProvider {
    pub const fn new(url: String) -> Self {
        Self { url }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EstimateBaseFeeResponse {
    pub block_number: i64,
    pub base_fee: f64,
    pub blob_base_fee: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EstimateBaseFeeQuery {
    pub block_number: i64,
}

impl PreconfFeeProvider for TaiyiPreconfFeeProvider {
    async fn get(&self, slot: u64) -> Result<PreconfFee, reqwest::Error> {
        let url = format!("{}/prediction/fee/estimate-base-fee", self.url);
        let query = EstimateBaseFeeQuery { block_number: slot as i64 };
        let estimate_fee: EstimateBaseFeeResponse =
            Client::new().get(url).query(&query).send().await?.json().await?;
        Ok(PreconfFee {
            gas_fee: (estimate_fee.base_fee) as u128,
            blob_gas_fee: (estimate_fee.blob_base_fee) as u128,
        })
    }
}
