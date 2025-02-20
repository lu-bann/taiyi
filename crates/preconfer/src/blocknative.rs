use alloy_consensus::constants::GWEI_TO_WEI;
use reqwest::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EstimatedPrice {
    confidence: u32,
    price: f64,
    #[serde(rename = "maxPriorityFeePerGas")]
    max_priority_fee_per_gas: f64,
    #[serde(rename = "maxFeePerGas")]
    max_fee_per_gas: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockPrice {
    #[serde(rename = "blockNumber")]
    block_number: u64,
    #[serde(rename = "estimatedTransactionCount")]
    estimated_transaction_count: u32,
    #[serde(rename = "baseFeePerGas")]
    base_fee_per_gas: f64,
    #[serde(rename = "blobBaseFeePerGas")]
    blob_base_fee_per_gas: f64,
    #[serde(rename = "estimatedPrices")]
    estimated_prices: Vec<EstimatedPrice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GasPriceResponse {
    system: String,
    network: String,
    unit: String,
    #[serde(rename = "maxPrice")]
    max_price: f64,
    #[serde(rename = "currentBlockNumber")]
    current_block_number: u64,
    #[serde(rename = "msSinceLastBlock")]
    ms_since_last_block: u64,
    #[serde(rename = "blockPrices")]
    block_prices: Vec<BlockPrice>,
}

async fn fetch_gas_prices() -> Result<GasPriceResponse, Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.blocknative.com/gasprices/blockprices")
        .send()
        .await?
        .json::<GasPriceResponse>()
        .await?;
    Ok(response)
}

/// Returns the gas prices with confidence level 99
async fn fetch_gas_prices_cl_99() -> Result<GasPriceResponse, Error> {
    let response = fetch_gas_prices().await?;
    let gas_prices = response
        .block_prices
        .iter()
        .find(|bp| bp.estimated_prices.iter().any(|ep| ep.confidence == 99));
    match gas_prices {
        Some(gas_prices) => {
            let gas_prices = GasPriceResponse {
                system: response.system,
                network: response.network,
                unit: response.unit,
                max_price: response.max_price,
                current_block_number: response.current_block_number,
                ms_since_last_block: response.ms_since_last_block,
                block_prices: vec![gas_prices.clone()],
            };
            Ok(gas_prices)
        }
        None => panic!("No gas prices with confidence level 99"),
    }
}

/// Returns (max_priority_fee_per_gas, max_fee_per_gas, base_fee_per_gas, blob_base_fee_per_gas) in wei
pub async fn get_gas_prices() -> (u64, u64, u64, u64) {
    let response = fetch_gas_prices_cl_99().await.expect("Failed to fetch gas prices");
    let block_price = &response.block_prices[0];
    let estimated_price = &block_price.estimated_prices[0];
    (
        estimated_price.max_priority_fee_per_gas as u64 * GWEI_TO_WEI,
        estimated_price.max_fee_per_gas as u64 * GWEI_TO_WEI,
        block_price.base_fee_per_gas as u64 * GWEI_TO_WEI,
        block_price.blob_base_fee_per_gas as u64 * GWEI_TO_WEI,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_gas_prices() {
        let response = fetch_gas_prices().await.unwrap();
        assert_eq!(response.system, "ethereum");
        assert_eq!(response.network, "main");
        assert_eq!(response.unit, "gwei");
        assert!(!response.block_prices.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_gas_prices_cl_99() {
        let response = fetch_gas_prices_cl_99().await.unwrap();
        assert_eq!(response.system, "ethereum");
        assert_eq!(response.network, "main");
        assert_eq!(response.unit, "gwei");
        assert_eq!(response.block_prices.len(), 1);
        let block_price = &response.block_prices[0];
        assert!(block_price.estimated_prices.iter().any(|ep| ep.confidence == 99));
    }
}
