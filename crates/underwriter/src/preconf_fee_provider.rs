use alloy::providers::Provider;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::future::Future;
use taiyi_primitives::PreconfFee;

#[cfg_attr(test, mockall::automock)]
pub trait PreconfFeeProvider {
    fn get(&self, slot: u64) -> impl Future<Output = eyre::Result<PreconfFee>>;
}

#[derive(Debug)]
pub struct TaiyiPreconfFeeProvider<P: Provider> {
    url: Option<String>,
    provider: P,
}

impl<P: Provider> TaiyiPreconfFeeProvider<P> {
    pub const fn new(url: Option<String>, provider: P) -> Self {
        Self { url, provider }
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

impl<P: Provider> PreconfFeeProvider for TaiyiPreconfFeeProvider<P> {
    async fn get(&self, slot: u64) -> eyre::Result<PreconfFee> {
        let preconf_fee = if let Some(url) = self.url.clone() {
            let url = format!("{}/prediction/fee/estimate-base-fee", url);
            let query = EstimateBaseFeeQuery { block_number: slot as i64 };
            let estimate_fee: EstimateBaseFeeResponse =
                Client::new().get(url).query(&query).send().await?.json().await?;
            PreconfFee {
                gas_fee: (estimate_fee.base_fee) as u128,
                blob_gas_fee: (estimate_fee.blob_base_fee) as u128,
            }
        } else {
            let estimate = self.provider.estimate_eip1559_fees().await?;
            let blob_gas_fee = self.provider.get_blob_base_fee().await?;
            PreconfFee { gas_fee: estimate.max_fee_per_gas, blob_gas_fee }
        };
        Ok(preconf_fee)
    }
}
