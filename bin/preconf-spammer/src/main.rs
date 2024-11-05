#![allow(clippy::unwrap_used)]

use std::{str::FromStr, sync::Arc};

use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use ethereum_consensus::{
    clock, deneb::Context, networks::Network, phase0::mainnet::SLOTS_PER_EPOCH,
};
use eyre::Result;
use futures::StreamExt;
use reqwest::Url;
use taiyi_primitives::{
    AvailableSlotResponse, PreconfRequest, PreconfResponse, PreconfTx, TipTransaction,
};
use tracing::{info, Level};

sol!(
    #[sol(rpc)]
    contract TaiyiCore{
        function getTipNonce(address sender) public view returns (uint256 nonce);
        function getPreconfNonce(address sender) public view returns (uint256 nonce);
    }

    #[sol(rpc)]
    contract ERC20Permit {
        #[derive(Debug)]
        function nonces(address owner) public view virtual override returns (uint256);

        #[derive(Debug)]
        function name() public view virtual override returns (string memory);
    }
);

#[derive(Parser)]
struct Opts {
    /// reth url
    #[clap(long = "rpc_url")]
    rpc_url: Url,

    /// Preconfer URL
    #[clap(long = "taiyu_preconfer_url", default_value = "http://localhost:18550")]
    taiyi_preconfer_url: String,

    /// Private key to sign the transaction
    #[clap(long = "private_key")]
    private_key: String,

    /// Number of transactions to send every slot
    #[clap(long = "num_txs", default_value = "1")]
    num_txs: u64,

    /// Taiyi core contract address
    #[clap(long = "taiyi_core_address")]
    taiyi_core_address: String,

    /// Receiver address
    #[clap(long = "receiver_address")]
    receiver: String,

    /// Network
    #[clap(long = "network", default_value = "holeksy")]
    network: String,

    /// token to perform the transfer of
    #[clap(long = "token_address")]
    token_address: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    initialize_tracing_log();
    info!("starting spammer");
    let opts = Opts::parse();

    let taiyi_core_address: Address = opts.taiyi_core_address.parse()?;
    let receiver = opts.receiver.parse()?;
    let token = opts.token_address.parse()?;

    let wallet: PrivateKeySigner = opts.private_key.parse().expect("should parse private key");
    let sender = wallet.address();

    let provider = ProviderBuilder::new().on_http(opts.rpc_url);

    let chain_id = provider.get_chain_id().await?;
    let taiyi_core_contract =
        TaiyiCore::TaiyiCoreInstance::new(taiyi_core_address, provider.clone());
    let token_contract = ERC20Permit::ERC20PermitInstance::new(token, provider.clone());
    let token_name = token_contract.name().call().await?._0;

    let network: Network = opts.network.into();
    let context: Context = network.try_into()?;
    let genesis_time = match context.genesis_time() {
        Ok(genesis_time) => genesis_time,
        Err(_) => context.min_genesis_time + context.genesis_delay,
    };

    let mut slot_stream =
        clock::from_system_time(genesis_time, context.seconds_per_slot, SLOTS_PER_EPOCH)
            .into_stream();

    let slots_url = Url::from_str(&opts.taiyi_preconfer_url)
        .expect("preconfer url missing")
        .join("commitments/v1/slots")?;
    let preconf_request_url = Url::from_str(&opts.taiyi_preconfer_url)
        .expect("preconfer url missing")
        .join("commitments/v1/preconf_request")?;

    let client = Arc::new(reqwest::Client::new());

    loop {
        let available_slot_response =
            client.get(slots_url.clone()).send().await?.json::<AvailableSlotResponse>().await?;
        let current_slot = available_slot_response.current_slot;

        if available_slot_response.available_slots.is_empty() {
            tracing::warn!("No available slots");
        }

        let mut future_slots = available_slot_response
            .available_slots
            .iter()
            .map(|s| s.slot)
            .filter(|slot| slot > &current_slot)
            .collect::<Vec<_>>()
            .into_iter();

        loop {
            if let Some(slot) = slot_stream.next().await {
                if let Some(next_available_slot) = future_slots.clone().peekable().peek() {
                    if (slot + 1) == *next_available_slot {
                        info!(
                            "Found next slot for which preconf reques could be sent: {}",
                            slot + 1
                        );

                        // Get nonce and estimate gasprice
                        let estimate = provider.estimate_eip1559_fees(None).await?;
                        let pre_pay = U256::from(estimate.max_fee_per_gas);
                        let after_pay = U256::from(estimate.max_priority_fee_per_gas);
                        let tip_nonce = taiyi_core_contract.getTipNonce(sender).call().await?.nonce;
                        let preconf_nonce =
                            taiyi_core_contract.getPreconfNonce(sender).call().await?.nonce;

                        let target_slot = future_slots.next().unwrap();

                        let tip_tx = TipTransaction {
                            gas_limit: U256::from(21_000),
                            from: sender,
                            to: taiyi_core_address,
                            pre_pay,
                            after_pay,
                            nonce: tip_nonce,
                            target_slot: U256::from(target_slot), /* sets the target slot to the next slot */
                        };

                        let tip_tx_signature = wallet
                            .sign_hash(&keccak256(tip_tx.tip_tx_hash(U256::from(chain_id))))
                            .await?;

                        let value = U256::from(100);
                        let slot_start_timestamp = genesis_time + (slot * context.seconds_per_slot);
                        let deadline = U256::from(slot_start_timestamp + context.seconds_per_slot); // deadline is the start of the next slot

                        let nonce = token_contract.nonces(sender).call().await?._0;

                        let permit_data = permit::sign_erc2612_permit(
                            token,
                            taiyi_core_address,
                            value,
                            U256::from(deadline),
                            nonce,
                            wallet.clone(),
                            U256::from(chain_id),
                            token_name.clone(),
                        )
                        .await
                        .unwrap();

                        let mut preconf_tx = PreconfTx::new(
                            sender,
                            receiver,
                            value,
                            Bytes::default(),
                            U256::from(21000),
                            preconf_nonce,
                            Bytes::default(),
                            Some(permit_data),
                        );

                        let preconf_tx_hash = preconf_tx.hash();
                        let preconf_tx_signature =
                            wallet.sign_hash(&preconf_tx_hash).await.unwrap();
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
                    }
                } else {
                    tracing::warn!("No more future slots");
                    break;
                }
            }
        }
    }
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

mod permit;
