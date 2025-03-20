#![cfg(test)]

use std::{path::Path, str::FromStr, sync::Mutex, time::Duration};

use alloy_consensus::TxEnvelope;
use alloy_eips::{eip4844::DATA_GAS_PER_BLOB, BlockNumberOrTag};
use alloy_primitives::{Address, TxHash, U256};
use alloy_provider::{
    network::{Ethereum, EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::{BlockTransactionsKind, TransactionRequest};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use ethereum_consensus::deneb::Context;
use reqwest::{Response, StatusCode, Url};
use serde::{Deserialize, Serialize};
use taiyi_cmd::{initialize_tracing_log, PreconferCommand};
use taiyi_preconfer::{
    context_ext::ContextExt, AVAILABLE_SLOT_PATH, PRECONF_FEE_PATH, RESERVE_BLOCKSPACE_PATH,
    SUBMIT_TRANSACTION_PATH, SUBMIT_TYPEA_TRANSACTION_PATH,
};
use taiyi_primitives::{
    BlockspaceAllocation as BlockspaceAlloc, PreconfFeeResponse, PreconfRequest, PreconfResponse,
    SignedConstraints, SlotInfo, SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use tokio::time::sleep;
use tracing::{error, info};
use uuid::Uuid;

use crate::constant::{
    FUNDING_SIGNER_PRIVATE, PRECONFER_BLS_SK, PRECONFER_ECDSA_SK, SLOT_CHECK_INTERVAL_SECONDS,
};

lazy_static::lazy_static! {
    static ref LOG_INIT: Mutex<bool> = Mutex::new(false);
    static ref FUNDING_SIGNER_LOCK: Mutex<()> = Mutex::new(());
}

sol! {
    struct BlockspaceAllocation {
        uint256 gasLimit;
        address sender;
        address recipient;
        uint256 deposit;
        uint256 tip;
        uint256 targetSlot;
        uint256 blobCount;
    }
    struct PreconfRequestBType {
        BlockspaceAllocation blockspaceAllocation;
        bytes blockspaceAllocationSignature;
        bytes gatewaySignedBlockspaceAllocation;
        bytes rawTx;
        bytes gatewaySignedRawTx;
    }
    function getTip(PreconfRequestBType calldata preconfRequestBType);
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ErrorResponse {
    pub code: u64,
    pub message: String,
}

#[derive(Clone)]
pub struct TestConfig {
    pub working_dir: String,
    pub execution_url: String,
    pub beacon_url: String,
    pub relay_url: String,
    pub taiyi_port: u16,
    pub context: Context,
    pub taiyi_core: Address,
}

impl std::fmt::Debug for TestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestConfig {{ working_dir: {:?}, execution_url: {:?}, beacon_url: {:?}, relay_url: {:?}, taiyi_port: {:?}, taiyi_core: {:?} }}", self.working_dir, self.execution_url, self.beacon_url, self.relay_url, self.taiyi_port, self.taiyi_core)
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

        let taiyi_core = std::env::var("TAIYI_CORE_ADDRESS")
            .expect("TAIYI_CORE_ADDRESS environment variable not set");
        let taiyi_port = std::env::var("TAIYI_PORT")
            .map(|res| res.parse::<u16>().expect("TAIYI_PORT is not a valid port"))
            .unwrap_or_else(|_| get_available_port());
        let config_path = format!("{}/{}/config.yaml", working_dir, "el_cl_genesis_data");
        let p = Path::new(&config_path);
        info!("config file path: {:?}", p);
        let context = Context::try_from_file(p).unwrap();
        let taiyi_core = Address::from_str(&taiyi_core).unwrap();
        let config = Self {
            working_dir,
            execution_url,
            beacon_url,
            relay_url,
            taiyi_port,
            context,
            taiyi_core,
        };
        info!("test config: {:?}", config);
        config
    }

    pub fn taiyi_url(&self) -> String {
        format!("http://localhost:{}", self.taiyi_port)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreconfTypeAJson {
    pub gateway_address: String,
    pub preconf_gateway_signature: String,
    pub slot: String,
    pub tip_transaction_hash: String,
    pub user_transaction_hashes: Vec<String>,
    pub sequence_number: String,
    pub anchor_transaction_hash: String,
}

impl PreconfTypeAJson {
    pub fn from_file(path: &str) -> eyre::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let preconf = serde_json::from_reader(reader)?;
        Ok(preconf)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreconfTypeBJson {
    pub gateway_address: String,
    pub preconf_gateway_signature: String,
    pub slot: String,
    pub user_transaction_hash: String,
    pub gateway_get_tip_transaction_hash: String,
    pub gateway_sponsorship_transaction_hash: String,
}

impl PreconfTypeBJson {
    pub fn from_file(path: &str) -> eyre::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let preconf = serde_json::from_reader(reader)?;
        Ok(preconf)
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
        config.taiyi_core.to_string().as_str(),
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

pub async fn get_available_slot(taiyi_url: &str) -> eyre::Result<Vec<SlotInfo>> {
    let client = reqwest::Client::new();
    let res = client.get(&format!("{}{}", taiyi_url, AVAILABLE_SLOT_PATH)).send().await?;
    let res_b = res.bytes().await?;
    let available_slots = serde_json::from_slice::<Vec<SlotInfo>>(&res_b)?;
    Ok(available_slots)
}

pub async fn get_preconf_fee(taiyi_url: &str, slot: u64) -> eyre::Result<PreconfFeeResponse> {
    let client = reqwest::Client::new();
    let res = client.post(&format!("{}{}", taiyi_url, PRECONF_FEE_PATH)).json(&slot).send().await?;
    let res_b = res.bytes().await?;
    let preconf_fee = serde_json::from_slice::<PreconfFeeResponse>(&res_b)?;
    Ok(preconf_fee)
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

pub async fn wait_until_deadline_of_slot(
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

pub async fn get_block_from_slot(beacon_url: &str, slot: u64) -> eyre::Result<u64> {
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/eth/v2/beacon/blocks/{}", beacon_url, slot))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let block_number = response["data"]["message"]["body"]["execution_payload"]["block_number"]
        .as_str()
        .unwrap()
        .parse::<u64>()?;

    Ok(block_number)
}

pub async fn verify_tx_in_block(
    execution_url: &str,
    block_number: u64,
    target_tx_hash: TxHash,
) -> eyre::Result<()> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(execution_url).await?;

    let tx_receipt =
        provider.get_transaction_by_hash(target_tx_hash).await?.expect("tx receipt not found");
    assert_eq!(tx_receipt.block_number.expect("expect block number"), block_number);
    Ok(())
}

pub async fn verify_txs_inclusion(execution_url: &str, txs: Vec<TxEnvelope>) -> eyre::Result<()> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(execution_url).await?;

    for tx in &txs {
        let tx_receipt = provider.get_transaction_by_hash(*tx.tx_hash()).await?;
        assert!(tx_receipt.is_some());
    }

    Ok(())
}

pub async fn generate_tx(
    execution_url: &str,
    signer: PrivateKeySigner,
) -> eyre::Result<TxEnvelope> {
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
        .with_nonce(nonce)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;
    Ok(transaction)
}

pub async fn generate_tx_with_nonce(
    execution_url: &str,
    signer: PrivateKeySigner,
    nonce: u64,
) -> eyre::Result<TxEnvelope> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let fees = provider.estimate_eip1559_fees(None).await?;
    let wallet = EthereumWallet::from(signer);
    info!("Transaction nonce: {}", nonce);
    let transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(1000))
        .with_nonce(nonce)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;
    Ok(transaction)
}

pub async fn generate_reserve_blockspace_request(
    signer_private: PrivateKeySigner,
    target_slot: u64,
    gas_limit: u64,
    blob_count: u64,
    preocnf_fee: PreconfFeeResponse,
    chain_id: u64,
) -> (BlockspaceAlloc, String) {
    let fee = preocnf_fee.gas_fee * (gas_limit as u128)
        + preocnf_fee.blob_gas_fee * ((blob_count * DATA_GAS_PER_BLOB) as u128);
    let fee = U256::from(fee / 2);
    let recepient = PRECONFER_ECDSA_SK.parse::<PrivateKeySigner>().unwrap();
    let request = BlockspaceAlloc {
        target_slot,
        sender: signer_private.address(),
        recipient: recepient.address(),
        deposit: fee,
        tip: fee,
        gas_limit,
        blob_count: blob_count.try_into().unwrap(),
    };
    info!("block space allocation request: {:?}", request);
    let signature =
        hex::encode(signer_private.sign_hash(&request.hash(chain_id)).await.unwrap().as_bytes());
    (request, format!("0x{signature}"))
}

pub async fn generate_submit_transaction_request(
    signer_private: PrivateKeySigner,
    tx: TxEnvelope,
    request_id: Uuid,
) -> (SubmitTransactionRequest, String) {
    let request = SubmitTransactionRequest { transaction: tx, request_id };
    let signature =
        hex::encode(signer_private.sign_hash(&request.digest()).await.unwrap().as_bytes());
    (request, format!("0x{signature}"))
}

pub async fn generate_type_a_request(
    signer: PrivateKeySigner,
    target_slot: u64,
    execution_url: &str,
    fee: PreconfFeeResponse,
) -> eyre::Result<(SubmitTypeATransactionRequest, String)> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let fees = provider.estimate_eip1559_fees(None).await?;
    let wallet = EthereumWallet::from(signer.clone());
    let nonce = provider.get_transaction_count(sender).await?;
    let tip_transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(fee.gas_fee * 21_000 * 2))
        .with_nonce(nonce)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;

    let preconf_transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(1000))
        .with_nonce(nonce + 1)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;

    let request = SubmitTypeATransactionRequest::new(
        vec![TxEnvelope::from(preconf_transaction)],
        TxEnvelope::from(tip_transaction),
        target_slot,
    );
    let signature = hex::encode(signer.sign_hash(&request.digest()).await.unwrap().as_bytes());
    Ok((request, format!("0x{signature}")))
}

pub async fn generate_type_a_request_with_nonce(
    signer: PrivateKeySigner,
    target_slot: u64,
    execution_url: &str,
    fee: PreconfFeeResponse,
    nonce: u64,
) -> eyre::Result<(SubmitTypeATransactionRequest, String)> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let fees = provider.estimate_eip1559_fees(None).await?;
    let wallet = EthereumWallet::from(signer.clone());
    let tip_transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(fee.gas_fee * 21_000 * 2))
        .with_nonce(nonce)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;

    let preconf_transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(1000))
        .with_nonce(nonce + 1)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;

    let request = SubmitTypeATransactionRequest::new(
        vec![TxEnvelope::from(preconf_transaction)],
        TxEnvelope::from(tip_transaction),
        target_slot,
    );
    let signature = hex::encode(signer.sign_hash(&request.digest()).await.unwrap().as_bytes());
    Ok((request, format!("0x{signature}")))
}

pub async fn send_reserve_blockspace_request(
    request: BlockspaceAlloc,
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

pub async fn send_type_a_request(
    request: SubmitTypeATransactionRequest,
    signature: String,
    taiyi_url: &str,
) -> eyre::Result<Response> {
    let request_endpoint =
        Url::parse(&taiyi_url).unwrap().join(SUBMIT_TYPEA_TRANSACTION_PATH).unwrap();
    let response = reqwest::Client::new()
        .post(request_endpoint.clone())
        .header("content-type", "application/json")
        .header("x-luban-signature", signature)
        .json(&request)
        .send()
        .await?;
    Ok(response)
}

pub async fn new_account(config: &TestConfig) -> eyre::Result<PrivateKeySigner> {
    // because we are using only one funding signer lock
    // using lock to avoid two tests create two account with the same nonce on funding account
    let _lock = FUNDING_SIGNER_LOCK.lock().unwrap();
    let funding: PrivateKeySigner = FUNDING_SIGNER_PRIVATE.parse()?;
    let wallet = EthereumWallet::new(funding.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_builtin(&config.execution_url)
        .await?;
    let new_signer = PrivateKeySigner::random();
    let mut tx = TransactionRequest::default();
    tx.set_to(new_signer.address());
    tx.set_value(U256::from(1000000000000000000u128));
    let send = provider.send_transaction(tx).await?;
    let _ = send.get_receipt().await?;
    Ok(new_signer)
}

pub async fn setup_env() -> eyre::Result<(tokio::task::JoinHandle<()>, TestConfig)> {
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
