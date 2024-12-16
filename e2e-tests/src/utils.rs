#![cfg(test)]

use std::{path::Path, time::Duration};

use alloy_consensus::TxEnvelope;
use alloy_primitives::U256;
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use ethereum_consensus::deneb::Context;
use reqwest::Url;
use taiyi_cmd::{initialize_tracing_log, PreconferCommand};
use taiyi_preconfer::GetSlotResponse;
use taiyi_primitives::{
    BlockspaceAllocation, ContextExt, PreconfRequest, PreconfResponse, SignedConstraints,
};
use tokio::time::sleep;
use tracing::{error, info};

use crate::constant::{
    PRECONFER_BLS_SK, PRECONFER_ECDSA_SK, PRECONF_REQUEST_PATH, SLOT_CHECK_INTERVAL_SECONDS,
};

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
        "--bls_sk",
        PRECONFER_BLS_SK,
        "--ecdsa_sk",
        PRECONFER_ECDSA_SK,
        "--network",
        &network_dir,
        "--execution_client_url",
        &config.execution_url,
        "--beacon_client_url",
        &config.beacon_url,
        "--relay_url",
        &config.relay_url,
        "--taiyi_rpc_port",
        config.taiyi_port.to_string().as_str(),
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
    let res = client.get(&format!("{}/commitments/v1/slots", taiyi_url)).send().await?;
    let res_b = res.bytes().await?;
    let available_slots = serde_json::from_slice::<Vec<GetSlotResponse>>(&res_b)?;
    Ok(available_slots)
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
    info!("get constraints from relay: {:?}", res_b);
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
    let transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(1000))
        .with_nonce(nonce)
        .with_gas_limit(21_0000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;
    Ok(transaction)
}

pub async fn submit_preconf_request(
    taiyi_url: &str,
    tx: &TxEnvelope,
    target_slot: u64,
) -> eyre::Result<PreconfResponse> {
    let preconf_request = PreconfRequest {
        allocation: BlockspaceAllocation::default(),
        transaction: Some(tx.clone()),
        target_slot,
    };
    let request_endpoint = Url::parse(&taiyi_url).unwrap().join(PRECONF_REQUEST_PATH).unwrap();
    let response =
        reqwest::Client::new().post(request_endpoint.clone()).json(&preconf_request).send().await?;

    let res_body = response.json::<PreconfResponse>().await?;
    Ok(res_body)
}

pub async fn setup_env() -> eyre::Result<(tokio::task::JoinHandle<()>, TestConfig)> {
    initialize_tracing_log();
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
