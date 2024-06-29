use std::marker::PhantomData;

use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_provider::{network::Ethereum, Provider};
use alloy_transport::Transport;

pub trait BaseFeeFetcher {
    fn get_optimal_base_gas_fee(
        &self,
    ) -> impl std::future::Future<Output = eyre::Result<u128>> + Send;
}

#[derive(Debug)]
pub struct LubanFeeFetcher {
    url: String,
}

impl LubanFeeFetcher {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl BaseFeeFetcher for LubanFeeFetcher {
    async fn get_optimal_base_gas_fee(&self) -> eyre::Result<u128> {
        let response = reqwest::get(self.url.clone()).await?;
        let body = response.bytes().await?;

        let body_str = String::from_utf8_lossy(&body);
        let res = body_str.parse::<u128>()?;
        Ok(res)
    }
}

#[derive(Debug)]
pub struct ExecutionClientFeeFetcher<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    provider: P,
    phantom: PhantomData<T>,
}

impl<T, P> ExecutionClientFeeFetcher<T, P>
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

impl<T, P> BaseFeeFetcher for ExecutionClientFeeFetcher<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    async fn get_optimal_base_gas_fee(&self) -> eyre::Result<u128> {
        let block = self
            .provider
            .get_block(BlockId::Number(BlockNumberOrTag::Latest), false)
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
    use crate::base_fee_fetcher::{BaseFeeFetcher, LubanFeeFetcher};

    #[tokio::test]
    #[ignore = "need local infra"]
    async fn test_get_optimal_base_gas_fee() -> eyre::Result<()> {
        let fetcher = LubanFeeFetcher::new("http://127.0.0.1:3000/base-fee".to_string());
        let res = fetcher.get_optimal_base_gas_fee().await?;
        assert_eq!(res, 0);
        Ok(())
    }
}
