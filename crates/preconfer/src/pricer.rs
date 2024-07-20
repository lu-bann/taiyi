use std::marker::PhantomData;

use alloy::rpc::types::BlockTransactionsKind;
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    network::Ethereum,
    providers::Provider,
    transports::Transport,
};

pub trait PreconfPricer {
    fn get_optimal_base_gas_fee(
        &self,
    ) -> impl std::future::Future<Output = eyre::Result<u128>> + Send;
    /// Simply scale up the current base fee by 10% per block
    fn price_preconf(
        &self,
        block_lookahead: u128,
    ) -> impl std::future::Future<Output = eyre::Result<u128>> + Send
    where
        Self: std::marker::Sync,
    {
        async move {
            let current_base_fee: u128 = self.get_optimal_base_gas_fee().await?;
            let current_base_fee_f64: f64 = current_base_fee as f64;
            let block_lookahead_f64: f64 = block_lookahead as f64;
            let projected_base_fee_f64: f64 =
                current_base_fee_f64 * (1.0_f64 + 0.1_f64).powf(block_lookahead_f64);
            Ok(projected_base_fee_f64 as u128)
        }
    }
}

#[derive(Debug)]
pub struct LubanFeePricer {
    url: String,
}

impl LubanFeePricer {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl PreconfPricer for LubanFeePricer {
    async fn get_optimal_base_gas_fee(&self) -> eyre::Result<u128> {
        let response = reqwest::get(self.url.clone()).await?;
        let body = response.bytes().await?;

        let body_str = String::from_utf8_lossy(&body);
        let res = body_str.parse::<u128>()?;
        Ok(res)
    }
}

#[derive(Debug)]
pub struct ExecutionClientFeePricer<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    provider: P,
    phantom: PhantomData<T>,
}

impl<T, P> ExecutionClientFeePricer<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            phantom: PhantomData,
        }
    }
}

impl<T, P> PreconfPricer for ExecutionClientFeePricer<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    async fn get_optimal_base_gas_fee(&self) -> eyre::Result<u128> {
        let block = self
            .provider
            .get_block(
                BlockId::Number(BlockNumberOrTag::Latest),
                BlockTransactionsKind::Hashes,
            )
            .await?;
        block
            .and_then(|block| {
                let base_fee = block.header.base_fee_per_gas?;
                Some(base_fee)
            })
            .ok_or_else(|| eyre::eyre!("base fee not found"))
    }
}

#[cfg(test)]
mod tests {
    use crate::pricer::{LubanFeePricer, PreconfPricer};

    #[tokio::test]
    #[ignore = "need local infra"]
    async fn test_get_optimal_base_gas_fee() -> eyre::Result<()> {
        let fetcher = LubanFeePricer::new("http://127.0.0.1:3000/base-fee".to_string());
        let res = fetcher.get_optimal_base_gas_fee().await?;
        assert_eq!(res, 0);
        Ok(())
    }
}
