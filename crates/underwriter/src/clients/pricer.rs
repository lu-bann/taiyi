use alloy_provider::Provider;
use serde::{Deserialize, Serialize};
use taiyi_primitives::PreconfFeeResponse;

use crate::error::PricerError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EstimateBaseFeeResponse {
    pub block_number: i64,
    pub base_fee: f64,
    pub blob_base_fee: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EstimateBaseFeeQuery {
    pub block_number: i64,
}

#[derive(Debug, Clone)]
pub struct Pricer<F> {
    pub pricer: F,
}

impl<F> Pricer<F>
where
    F: PreconfPricer + Sync,
{
    pub fn new(pricer: F) -> Self {
        Self { pricer }
    }
}

pub trait PreconfPricer {
    fn get_preconf_fee(
        &self,
        slot: u64,
    ) -> impl std::future::Future<Output = Result<PreconfFeeResponse, PricerError>> + std::marker::Send;
}

#[derive(Debug, Clone)]
pub struct TaiyiPricer {
    client: reqwest::Client,
    url: String,
}

impl TaiyiPricer {
    pub fn new(url: String) -> Self {
        Self { client: reqwest::Client::new(), url }
    }

    pub async fn get_preconf_fee(&self, slot: u64) -> Result<PreconfFeeResponse, PricerError> {
        let url = format!("{}/prediction/fee/estimate-base-fee", self.url);
        let query = EstimateBaseFeeQuery { block_number: slot as i64 };
        let response = self.client.get(url).query(&query).send().await?;
        let body = response.text().await?;
        let estimate_fee = serde_json::from_str::<EstimateBaseFeeResponse>(&body)
            .map_err(|e| PricerError::ParseError(e.to_string()))?;
        Ok(PreconfFeeResponse {
            gas_fee: (estimate_fee.base_fee) as u128,
            blob_gas_fee: (estimate_fee.blob_base_fee) as u128,
        })
    }
}

impl PreconfPricer for TaiyiPricer {
    async fn get_preconf_fee(&self, slot: u64) -> Result<PreconfFeeResponse, PricerError> {
        self.get_preconf_fee(slot).await
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionClientPricer<P> {
    provider: P,
}

impl<P> ExecutionClientPricer<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> PreconfPricer for ExecutionClientPricer<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    async fn get_preconf_fee(&self, _slot: u64) -> Result<PreconfFeeResponse, PricerError> {
        let estimate = self.provider.estimate_eip1559_fees().await?;
        let blob_gas_fee = self.provider.get_blob_base_fee().await?;
        Ok(PreconfFeeResponse { gas_fee: estimate.max_fee_per_gas, blob_gas_fee })
    }
}
