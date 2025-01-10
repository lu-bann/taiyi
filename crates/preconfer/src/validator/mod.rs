use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT;
use reqwest::Url;
use reth_revm::primitives::EnvKzgSettings;
use taiyi_primitives::PreconfRequest;

use crate::{clients::execution_client::ExecutionClient, contract::TaiyiCoreInstance};

/// A [`PreconfValidator`] implementation that validates ethereum transaction.
#[derive(Debug, Clone)]
pub struct PreconfValidator {
    /// The current max gas limit
    pub block_gas_limit: u64,
    /// Stores the setup and parameters needed for validating KZG proofs.
    pub kzg_settings: EnvKzgSettings,
    /// max constraints per block
    pub max_constraints: u64,
    /// Used to fetch latest state
    pub execution_client: ExecutionClient,
}

impl PreconfValidator {
    /// Create a new `TxValidator` instance.
    pub fn new(rpc_url: Url) -> Self {
        Self {
            block_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT,
            kzg_settings: EnvKzgSettings::default(),
            max_constraints: 256,
            execution_client: ExecutionClient::new(rpc_url),
        }
    }
}
