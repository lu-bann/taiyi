pub trait BaseFeeFetcher {
    async fn get_optimal_base_gas_fee(&self) -> eyre::Result<u64>;
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
    async fn get_optimal_base_gas_fee(&self) -> eyre::Result<u64> {
        let response = reqwest::get(self.url.clone()).await?;
        let body = response.bytes().await?;

        let body_str = String::from_utf8_lossy(&body);
        let res = body_str.parse::<u64>()?;
        Ok(res)
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
