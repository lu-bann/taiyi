#![allow(unused)]
use std::{
    env,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use alloy_network::TransactionBuilder;
use alloy_primitives::{address, Address, U256};
use alloy_rpc_types_eth::TransactionRequest;
use ethereum_consensus::networks::Network;
use eyre::Result;
use reqwest::Url;

use crate::types::{BlsSecretKeyWrapper, ExtraConfig, JwtSecretWrapper};

pub fn get_nanos_timestamp() -> Result<u64, SystemTimeError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64)
}

pub fn get_now_timestamp() -> Result<u64, SystemTimeError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs())
}

pub fn get_test_config() -> Result<ExtraConfig> {
    let engine_api = env::var("TAIYI_ENGINE_API").expect("Fail to read env TAIYI_ENGINE_API");
    let execution_api =
        env::var("TAIYI_EXECUTION_API").expect("Fail to read env TAIYI_EXECUTION_API");
    let beacon_api = env::var("TAIYI_BEACON_API").expect("Fail to read env TAIYI_BEACON_API");
    let jwt_secret = env::var("TAIYI_JWT_SECRET").expect("Fail to read env TAIYI_JWT_SECRET");
    Ok(ExtraConfig {
        engine_api: Url::parse(&engine_api)?,
        execution_api: Url::parse(&execution_api)?,
        beacon_api: Url::parse(&beacon_api)?,
        fee_recipient: address!("dd5DFB73a16B21a6D6bAfF278Fe05D97f71ACfD3"),
        builder_private_key: BlsSecretKeyWrapper::from(
            "0x6b845831c99c6bf43364bee624447d39698465df5c07f2cc4dca6e0acfbe46cd",
        ),
        engine_jwt: JwtSecretWrapper::try_from(jwt_secret.as_str())?,
        network: Network::from("holesky".to_string()),
    })
}

pub fn gen_test_tx_request(
    sender: Address,
    chain_id: u64,
    nonce: Option<u64>,
) -> TransactionRequest {
    TransactionRequest::default()
        .with_from(sender)
        // Burn it
        .with_to(Address::ZERO)
        .with_chain_id(chain_id)
        .with_nonce(nonce.unwrap_or(0))
        .with_value(U256::from(100))
        .with_gas_limit(21_000)
        .with_max_priority_fee_per_gas(1_000_000_000) // 1 gwei
        .with_max_fee_per_gas(20_000_000_000)
}
