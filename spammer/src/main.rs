#![allow(clippy::unwrap_used)]
#![allow(dead_code)]
#![allow(unused_imports)]
use std::collections::HashMap;

use alloy_eips::{self, merge::EPOCH_SLOTS};
use alloy_primitives::{Address, U256};
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types_beacon::events::HeadEvent;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use beacon_api_client::mainnet::Client as BeaconClient;
use clap::Parser;
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use reqwest::Url;
use tracing::info;

use crate::http::HttpClient;

mod http;
#[derive(Parser)]
struct Opts {
    /// execution_client_url
    #[clap(long = "execution_client_url", default_value = "http://localhost:8545")]
    execution_client_url: String,

    /// beacon_client_url
    #[clap(long = "beacon_client_url", default_value = "http://localhost:5062")]
    beacon_client_url: String,

    /// underwriter URL
    #[clap(long = "underwriter_url", default_value = "http://localhost:18550")]
    underwriter_url: String,

    /// Private key to sign the transaction
    #[clap(long = "private_key")]
    private_key: String,

    /// Taiyi core contract address
    #[clap(long = "taiyi_core_address")]
    taiyi_core_address: Address,
}

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt().init();

    let opts = Opts::parse();
    let signer: PrivateKeySigner = opts.private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(opts.execution_client_url.parse()?);
    let chain_id = provider.get_chain_id().await?;

    // Deposit into TaiyiCore
    // let contract_address = opts.taiyi_core_address;
    // let taiyi_escrow = TaiyiEscrow::new(contract_address, provider.clone());
    // let account_nonce = provider.get_transaction_count(signer.address()).await?;
    // info!("Account Nonce: {:?}", account_nonce);

    // let tx = taiyi_escrow
    //     .deposit()
    //     .value(U256::from(1_000_000_000_000_000_000u128))
    //     .into_transaction_request()
    //     .with_chain_id(chain_id)
    //     .with_gas_limit(100_000)
    //     .with_max_fee_per_gas(1000000010)
    //     .with_max_priority_fee_per_gas(1000000000)
    //     .with_nonce(account_nonce);
    // let pending_tx = provider.send_transaction(tx).await?;
    // info!("Deposit Transaction sent: {:?}", pending_tx.tx_hash());
    // let receipt = pending_tx.get_receipt().await?;
    // info!("Deposit Transaction mined in block: {:?}", receipt.block_number.unwrap());

    let http_client = HttpClient::new(opts.underwriter_url.parse()?, signer.clone(), chain_id);
    let beacon_client = BeaconClient::new(opts.beacon_client_url.parse::<Url>()?);
    let client = EventClient::new(reqwest::Client::new());

    let beacon_url_head_event =
        format!("{}eth/v1/events?topics=head", beacon_client.endpoint.as_str());

    let mut request_store = HashMap::new();

    // Query available slots and filter out the past slots
    let mut slots = http_client.slots().await?.iter().map(|slot| slot.slot).collect::<Vec<_>>();
    let head_slot = beacon_client.get_sync_status().await?.head_slot;
    info!("Head Slot: {:?}, filering older slots out of {} slots", head_slot, slots.len());
    slots.retain(|slot| *slot > head_slot);
    info!("Available slots: {:?}", slots.len());

    // Send reserve blockspace requests for the slots
    for slot in slots {
        info!("Reserving blockspace for slot: {:?}", slot);
        let request_id = http_client.reserve_blockspace(slot, opts.taiyi_core_address).await?;
        info!("Request ID: {:?}", request_id);
        request_store.insert(slot, request_id);
    }

    info!("Starts to subscribe to {}", beacon_url_head_event);
    let mut stream: mev_share_sse::client::EventStream<HeadEvent> =
        client.subscribe(&beacon_url_head_event).await?;

    while let Some(event) = stream.try_next().await? {
        let slot = event.slot;
        info!("Head Slot: {:?}", slot);
        let epoch = slot / EPOCH_SLOTS;
        let next_slot = slot + 1;

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let account_nonce = provider.get_transaction_count(signer.address()).await?;
        info!("Submitting transactions for next slot: {:?}", next_slot);

        if request_store.contains_key(&next_slot) {
            let data = http_client
                .submit_transaction_type_b(
                    *request_store.get(&next_slot).unwrap(),
                    account_nonce,
                    chain_id,
                )
                .await?;
            let commitment = hex::encode(data.commitment.unwrap().as_bytes());
            info!("Commitment type b: {:?}", format!("0x{}", commitment));

            let data =
                http_client.submit_type_a_request(next_slot, account_nonce + 1, chain_id).await?;
            let commitment = hex::encode(data.commitment.unwrap().as_bytes());
            info!("Commitment type a: {:?}", format!("0x{}", commitment));
            info!("Sequence Number: {:?}", data.sequence_num.unwrap());
        }

        if event.epoch_transition {
            info!("Epoch changed to: {:?}, querying underwriter for available slots..", epoch);
            let mut slots = http_client.slots().await?;
            let head_slot = beacon_client.get_sync_status().await?.head_slot;
            info!("Head Slot: {:?}, filering older slots out of {} slots", head_slot, slots.len());
            slots.retain(|slot| slot.slot > head_slot);
            info!("Available slots: {:?}", slots.len());

            for slot in slots {
                info!("Reserving blockspace for slot: {:?}", slot.slot);
                let request_id =
                    http_client.reserve_blockspace(slot.slot, opts.taiyi_core_address).await?;
                info!("Request ID: {:?}", request_id);
                request_store.insert(slot.slot, request_id);
            }
        }
    }

    Ok(())
}
