#![cfg(test)]

use std::{path::Path, sync::Mutex, time::Duration};

use alloy_consensus::TxEnvelope;
use alloy_primitives::U256;
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use ethereum_consensus::deneb::Context;
use reqwest::{Response, StatusCode, Url};
use taiyi_cmd::{initialize_tracing_log, PreconferCommand};
use taiyi_preconfer::GetSlotResponse;
use taiyi_primitives::{
    BlockspaceAllocation, ContextExt, EstimateFeeRequest, EstimateFeeResponse, PreconfRequest,
    PreconfResponse, SignedConstraints, SubmitTransactionRequest,
};
use tokio::time::sleep;
use tracing::{error, info};
use uuid::Uuid;

use crate::constant::{
    AVAILABLE_SLOT_PATH, ESTIMATE_TIP_PATH, PRECONFER_BLS_SK, PRECONFER_ECDSA_SK,
    RESERVE_BLOCKSPACE_PATH, SLOT_CHECK_INTERVAL_SECONDS, SUBMIT_TRANSACTION_PATH,
};

lazy_static::lazy_static! {
    static ref LOG_INIT: Mutex<bool> = Mutex::new(false);
}

#[derive(Clone)]
pub struct TestConfig {
    pub working_dir: String,
    pub execution_url: String,
    pub beacon_url: String,
    pub relay_url: String,
    pub taiyi_port: u16,
    pub context: Context,
}

impl std::fmt::Debug for TestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestConfig {{ working_dir: {:?}, execution_url: {:?}, beacon_url: {:?}, relay_url: {:?}, taiyi_port: {:?} }}", self.working_dir, self.execution_url, self.beacon_url, self.relay_url, self.taiyi_port)
    }
}

impl TestConfig {
    pub fn from_env() -> Self {
        let working_dir =
            std::env::var("WORKING_DIR").expect("WORKING_DIR environment variable not set");
        let execution_url =
            std::env::var("EXECUTION_URL").expect("EXECUTION_URL environment variable not set");
        let beacon_url =
            std::env::var("BEACON_URL").expect("BEACON_URL environment variable not set");
        let relay_url = std::env::var("RELAY_URL").expect("RELAY_URL environment variable not set");

        let taiyi_port = std::env::var("TAIYI_PORT")
            .map(|res| res.parse::<u16>().expect("TAIYI_PORT is not a valid port"))
            .unwrap_or_else(|_| get_available_port());
        let config_path = format!("{}/{}/config.yaml", working_dir, "el_cl_genesis_data");
        let p = Path::new(&config_path);
        info!("config file path: {:?}", p);
        let context = Context::try_from_file(p).unwrap();
        Self { working_dir, execution_url, beacon_url, relay_url, taiyi_port, context }
    }

    pub fn taiyi_url(&self) -> String {
        format!("http://localhost:{}", self.taiyi_port)
    }
}

fn get_available_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind to address");
    let port = listener.local_addr().unwrap().port();
    port
}

pub async fn wait_until_slot(beacon_node_url: &str, slot: u64) -> eyre::Result<()> {
    let client = reqwest::Client::new();
    info!("Waiting for slot greater than {}", slot);
    loop {
        // Query the beacon node for the current slot
        let url = format!("{}/eth/v1/beacon/headers", beacon_node_url);
        info!("Querying beacon node at {}", url);
        let response = client.get(url).send().await?;

        if response.status().is_success() {
            let json: serde_json::Value = response.json().await?;
            if let Some(current_slot) = json["data"][0]["header"]["message"]["slot"].as_str() {
                let current_slot = current_slot.parse::<u64>().expect("failed to parse slot");
                info!("Current slot: {}", current_slot);
                // Check if the current slot is greater than 32
                if current_slot > slot {
                    break;
                }
            }
        } else {
            error!("Failed to query beacon node: {}", response.status());
        }

        // Wait for a while before querying again
        sleep(Duration::from_secs(SLOT_CHECK_INTERVAL_SECONDS)).await;
    }

    Ok(())
}

pub async fn start_taiyi_command_for_testing(
    config: &TestConfig,
) -> eyre::Result<tokio::task::JoinHandle<()>> {
    // Initialize logging if not already initialized
    let network_dir = format!("{}/{}", config.working_dir, "el_cl_genesis_data");
    // Create a default instance of the main command or configure it as needed
    let taiyi_command = PreconferCommand::parse_from([
        "preconfer",
        "--bls-sk",
        PRECONFER_BLS_SK,
        "--ecdsa-sk",
        PRECONFER_ECDSA_SK,
        "--network",
        &network_dir,
        "--execution-rpc-url",
        &config.execution_url,
        "--beacon-rpc-url",
        &config.beacon_url,
        "--relay-url",
        &config.relay_url,
        "--taiyi-rpc-port",
        config.taiyi_port.to_string().as_str(),
        "--taiyi-escrow-address",
        "0xA791D59427B2b7063050187769AC871B497F4b3C",
    ]); // Assuming TaiyiCommand is the main command struct

    // Spawn the taiyi command in a background task
    let handle = tokio::spawn(async move {
        tokio::select! {
            res = taiyi_command.execute() => {
                error!("Taiyi command error: {:?}", res);
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down...");
            }
        }
    });

    Ok(handle)
}

pub async fn get_available_slot(taiyi_url: &str) -> eyre::Result<Vec<GetSlotResponse>> {
    let client = reqwest::Client::new();
    let res = client.get(&format!("{}{}", taiyi_url, AVAILABLE_SLOT_PATH)).send().await?;
    let res_b = res.bytes().await?;
    let available_slots = serde_json::from_slice::<Vec<GetSlotResponse>>(&res_b)?;
    Ok(available_slots)
}

pub async fn get_estimate_fee(taiyi_url: &str, slot: u64) -> eyre::Result<EstimateFeeResponse> {
    let client = reqwest::Client::new();
    let request = EstimateFeeRequest { slot };
    let res =
        client.post(&format!("{}{}", taiyi_url, ESTIMATE_TIP_PATH)).json(&request).send().await?;
    let res_b = res.bytes().await?;
    let estimate_fee = serde_json::from_slice::<EstimateFeeResponse>(&res_b)?;
    Ok(estimate_fee)
}

pub async fn health_check(taiyi_url: &str) -> eyre::Result<String> {
    let client = reqwest::Client::new();
    let res = client.get(&format!("{}/health", taiyi_url)).send().await?;
    let res_b = res.text().await?;
    Ok(res_b)
}

pub async fn get_constraints_from_relay(
    relay_url: &str,
    target_slot: u64,
) -> eyre::Result<Vec<SignedConstraints>> {
    let client = reqwest::Client::new();
    let res = client
        .get(&format!("{}/relay/v1/builder/constraints?slot={}", relay_url, target_slot))
        .send()
        .await?;
    let res_b = res.text().await?;
    info!("get constraints from relay for slot: {} : {:?}", target_slot, res_b);
    let constraints = serde_json::from_str::<Vec<SignedConstraints>>(&res_b)?;
    Ok(constraints)
}

pub async fn wati_until_deadline_of_slot(
    config: &TestConfig,
    target_slot: u64,
) -> eyre::Result<()> {
    let deadline = config.context.get_deadline_of_slot(target_slot);
    let time_diff = deadline.saturating_sub(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    );
    info!("Waiting for deadline of slot: {}, diff: {}", deadline, time_diff);
    tokio::time::sleep(Duration::from_secs(time_diff)).await;
    Ok(())
}

pub async fn generate_tx(execution_url: &str, signer_private: &str) -> eyre::Result<TxEnvelope> {
    let signer: PrivateKeySigner = signer_private.parse().unwrap();
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let fees = provider.estimate_eip1559_fees(None).await?;
    let wallet = EthereumWallet::from(signer);
    let nonce = provider.get_transaction_count(sender).await?;
    info!("Transaction nonce: {}", nonce);
    let transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(1000))
        // TODO: use the correct nonce, dont' why the nonce above is 3.
        .with_nonce(1)
        .with_gas_limit(21_0000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;
    Ok(transaction)
}

pub async fn generate_reserve_blockspace_request(
    signer_private: &str,
    target_slot: u64,
    fee: u128,
) -> (BlockspaceAllocation, String) {
    let signer: PrivateKeySigner = signer_private.parse().unwrap();

    let request = BlockspaceAllocation {
        target_slot,
        deposit: U256::from(fee * 21_000),
        gas_limit: 21_0000,
        num_blobs: 0,
    };
    let signature = hex::encode(signer.sign_hash(&request.digest()).await.unwrap().as_bytes());
    (request, format!("{}:0x{}", signer.address(), signature))
}

pub async fn generate_submit_transaction_request(
    signer_private: &str,
    request_id: Uuid,
    rpc_url: &str,
) -> (SubmitTransactionRequest, String) {
    let signer: PrivateKeySigner = signer_private.parse().unwrap();

    let transaction = generate_tx(rpc_url, PRECONFER_ECDSA_SK).await.unwrap();
    let request = SubmitTransactionRequest { transaction, request_id };
    let signature = hex::encode(signer.sign_hash(&request.digest()).await.unwrap().as_bytes());
    (request, format!("0x{}", signature))
}

pub async fn send_reserve_blockspace_request(
    request: BlockspaceAllocation,
    signature: String,
    taiyi_url: &str,
) -> eyre::Result<Response> {
    let request_endpoint = Url::parse(&taiyi_url).unwrap().join(RESERVE_BLOCKSPACE_PATH).unwrap();
    let response = reqwest::Client::new()
        .post(request_endpoint.clone())
        .header("content-type", "application/json")
        .header("x-luban-signature", signature)
        .json(&request)
        .send()
        .await?;
    Ok(response)
}

pub async fn send_submit_transaction_request(
    request: SubmitTransactionRequest,
    signature: String,
    taiyi_url: &str,
) -> eyre::Result<Response> {
    let request_endpoint = Url::parse(&taiyi_url).unwrap().join(SUBMIT_TRANSACTION_PATH).unwrap();
    let response = reqwest::Client::new()
        .post(request_endpoint.clone())
        .header("content-type", "application/json")
        .header("x-luban-signature", signature)
        .json(&request)
        .send()
        .await?;
    Ok(response)
}

pub async fn setup_env() -> eyre::Result<(tokio::task::JoinHandle<()>, TestConfig)> {
    std::env::set_var("RUST_LOG", "debug");
    init_log();
    let config = TestConfig::from_env();
    info!("Test Config: {:?}", config);
    info!("Waiting for slot greater than 32");
    // the first two epoch after genesis is not available for preconf
    wait_until_slot(&config.beacon_url, 32).await.expect("Failed to wait for slot greater than 32");

    info!("Starting preconfer");
    let taiyi_handle = start_taiyi_command_for_testing(&config).await?;
    tokio::time::sleep(Duration::from_secs(10)).await;
    Ok((taiyi_handle, config))
}

fn init_log() {
    let is_init = &mut LOG_INIT.lock().unwrap();
    if !**is_init {
        initialize_tracing_log();
        **is_init = true;
    }
}
