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
        let estimate = self.provider.estimate_eip1559_fees(None).await?;
        let blob_gas_fee = self.provider.get_blob_base_fee().await?;
        Ok(PreconfFeeResponse { gas_fee: estimate.max_fee_per_gas, blob_gas_fee })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_provider::{Provider, ProviderBuilder};

    use crate::clients::pricer::PreconfPricer;

    #[ignore = "requires a running pricing service"]
    #[tokio::test]
    async fn test_taiyi_pricer() {
        let pricer_url = std::env::var("PRICER_URL").unwrap();
        let pricer = crate::clients::pricer::TaiyiPricer::new(pricer_url);
        let rpc = "https://1rpc.io/holesky";
        // let rpc = "https://eth.merkle.io";
        let provider = ProviderBuilder::new().on_http(rpc.parse().unwrap());
        let block_number = provider.get_block_number().await.unwrap() + 1;

        let preconf_fee = pricer.get_preconf_fee(block_number).await;
        assert!(preconf_fee.is_ok());
        tokio::time::sleep(Duration::from_secs(12)).await;
        let header = provider
            .get_block_by_number(
                alloy_eips::BlockNumberOrTag::Number(block_number),
                alloy_rpc_types::BlockTransactionsKind::Full,
            )
            .await
            .unwrap()
            .unwrap()
            .header;
        println!(
            "actual base fee {:?}, actual blob base fee {:?}",
            header.base_fee_per_gas,
            header.blob_fee()
        );

        let preconf_fee = preconf_fee.unwrap();
        println!("Preconf fee: {:?}", preconf_fee);
    }

    #[tokio::test]
    async fn test_execution_client_pricer() -> eyre::Result<()> {
        let anvil = alloy_node_bindings::Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();
        let provider = ProviderBuilder::new().on_builtin(&rpc_url).await?;

        let pricer = crate::clients::pricer::ExecutionClientPricer::new(provider);
        let preconf_fee = pricer.get_preconf_fee(0).await;
        assert!(preconf_fee.is_ok());
        Ok(())
    }
}
