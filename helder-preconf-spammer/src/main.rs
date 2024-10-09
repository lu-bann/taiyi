#![allow(clippy::unwrap_used)]
use std::{str::FromStr, sync::Arc};

use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_primitives::{
    AvailableSlotResponse, PreconfRequest, PreconfResponse, PreconfTx, TipTransaction,
};
use tracing::{info, Level};

const RECEIVER_ADDR: &str = "luban.eth";
const _HELDER_GENESIS_TIME: u64 = 67677014190335;

#[derive(Parser)]
struct Opts {
    /// reth url
    #[clap(long = "execution_client_url", default_value = "http://localhost:8545")]
    execution_client_url: Url,

    /// Preconfer URL
    #[clap(long = "taiyu_preconfer_url", default_value = "http://localhost:18550")]
    taiyi_preconfer_url: String,

    /// Private key to sign the transaction
    #[clap(long = "private_key")]
    private_key: String,

    /// Number of transactions to send every slot
    #[clap(long = "num_txs", default_value = "1")]
    num_txs: u64,

    /// Luban core contract address
    #[clap(long = "luban_core_address")]
    luban_core_address: Address,
}

#[tokio::main]
async fn main() -> Result<()> {
    initialize_tracing_log();
    info!("starting helder spammer");
    let opts = Opts::parse();

    let wallet: PrivateKeySigner = opts.private_key.parse().expect("should parse private key");
    let sender = wallet.address();
    let reciever = Address::from_str(RECEIVER_ADDR).unwrap();
    let provider = ProviderBuilder::new().on_http(opts.execution_client_url);
    let chain_id = provider.get_chain_id().await?;

    let slots_url = Url::from_str(&opts.taiyi_preconfer_url)
        .expect("preconfer url missing")
        .join("commitments/v1/slots")?;
    let preconf_request_url = Url::from_str(&opts.taiyi_preconfer_url)
        .expect("preconfer url missing")
        .join("commitments/v1/preconf_request")?;

    let mut last_updated_slot: u64 = 0;
    let client = Arc::new(reqwest::Client::new());

    sol!(
        #[sol(rpc)]
        contract LubanCore{
            function getTipNonce(address sender) public view returns (uint256 nonce);
            function getPreconfNonce(address sender) public view returns (uint256 nonce);
        }
    );

    let contract = LubanCore::LubanCoreInstance::new(opts.luban_core_address, provider.clone());
    let mut tip_nonce = contract.getTipNonce(sender).call().await?.nonce;
    let mut preconf_nonce = contract.getPreconfNonce(sender).call().await?.nonce;

    loop {
        let result =
            client.get(slots_url.clone()).send().await?.json::<AvailableSlotResponse>().await?;
        let current_slot = result.current_slot;
        if current_slot < last_updated_slot {
            continue;
        }
        let future_slots = result
            .available_slots
            .iter()
            .map(|s| s.slot)
            .filter(|slot| slot > &current_slot)
            .collect::<Vec<_>>();
        if result.available_slots.is_empty() {
            tracing::warn!("No available slots");
        }

        for target_slot in &future_slots {
            info!("target slot: {}", target_slot);

            // Get nonce and estimate gasprice
            let estimate = provider.estimate_eip1559_fees(None).await?;
            // Increment nonce locally
            tip_nonce += U256::from(1);
            preconf_nonce += U256::from(1);

            // Prepay = base fee
            // Afterpay = priority fee
            let tip_tx = TipTransaction {
                gas_limit: U256::from(21_000),
                from: sender,
                to: Address::from_str(RECEIVER_ADDR).unwrap(),
                pre_pay: U256::from(estimate.max_fee_per_gas),
                after_pay: U256::from(estimate.max_priority_fee_per_gas),
                nonce: tip_nonce,
                target_slot: U256::from(*target_slot),
            };
            let tip_tx_signature =
                wallet.sign_hash(&keccak256(tip_tx.tip_tx_hash(U256::from(chain_id)))).await?;

            let mut preconf_tx = PreconfTx::new(
                sender,
                reciever,
                U256::from(100),
                Bytes::default(),
                U256::from(21000),
                preconf_nonce,
                Bytes::default(),
            );
            let preconf_tx_hash = preconf_tx.hash();
            let preconf_tx_signature = wallet.sign_hash(&preconf_tx_hash).await.unwrap();
            preconf_tx.signature = preconf_tx_signature.as_bytes().into();

            let preconf_request = PreconfRequest {
                tip_tx,
                tip_tx_signature,
                preconf_tx: Some(preconf_tx),
                preconfer_signature: None,
                preconf_req_signature: None,
            };

            let res = client
                .post(preconf_request_url.clone())
                .json(&preconf_request)
                .send()
                .await?
                .json::<PreconfResponse>()
                .await?;
            info!("res: {:?}", res);

            last_updated_slot = *future_slots.last().unwrap();
        }
    }

    // TODO: wait for target slot to be reached
    // Then submit the preconf tx with the calldata
    // let slot_start_timestamp = HELDER_GENESIS_TIME + (target_slot * 12);
    // let submit_start_time = slot_start_timestamp as i64 * 1_000_000_000;
    // let sleep_duration =
    //     submit_start_time - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
    // if sleep_duration.is_positive() {
    //     tokio::time::sleep(Duration::from_nanos(
    //         sleep_duration.try_into().expect("positive sleep duration"),
    //     ))
    //     .await;
    // }
}

fn initialize_tracing_log() {
    let level_env = std::env::var("RUST_LOG").unwrap_or("info".to_owned());
    let level = if let Ok(level) = Level::from_str(&level_env) {
        level
    } else {
        eprint!("Invalid log level {level_env}, defaulting to info");
        Level::INFO
    };

    tracing_subscriber::fmt()
        .compact()
        .with_max_level(level)
        .with_target(true)
        .with_file(true)
        .init();
}
