use std::{collections::HashMap, str::FromStr};

use alloy_eips::{eip4844::DATA_GAS_PER_BLOB, merge::EPOCH_SLOTS};
use alloy_primitives::{Address, U256};
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_beacon::events::HeadEvent;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use beacon_api_client::mainnet::Client as BeaconClient;
use clap::Parser;
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use reqwest::Url;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeResponse, PreconfResponse, PreconfResponseData, SlotInfo,
    SubmitTransactionRequest,
};
use tracing::info;
use uuid::Uuid;

#[derive(Parser)]
struct Opts {
    /// reth url
    #[clap(long = "execution_client_url", default_value = "http://localhost:8545")]
    execution_client_url: String,

    /// reth url
    #[clap(long = "beacon_client_url", default_value = "http://localhost:5062")]
    beacon_client_url: String,

    /// Preconfer URL
    #[clap(long = "gateway_url", default_value = "http://localhost:18550")]
    gateway_url: String,

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
    //
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

    let http_client = HttpClient::new(opts.gateway_url.parse()?, signer.clone());
    let beacon_client = BeaconClient::new(opts.beacon_client_url.parse::<Url>()?);
    let client = EventClient::new(reqwest::Client::new());
    let beacon_url_head_event =
        format!("{}eth/v1/events?topics=head", beacon_client.endpoint.as_str());

    let mut request_store = HashMap::new();

    // Query available slots and filter out the past slots
    let mut slots = http_client.slots().await?;
    let head_slot = beacon_client.get_sync_status().await?.head_slot;
    info!("Head Slot: {:?}, filering older slots out of {} slots", head_slot, slots.len());
    slots.retain(|slot| slot.slot > head_slot);
    info!("Available slots: {:?}", slots.len());

    // Send reserve blockspace requests for the slots
    for slot in slots {
        info!("Reserving blockspace for slot: {:?}", slot.slot);
        let request_id = http_client.reserve_blockspace(slot.slot).await?;
        info!("Request ID: {:?}", request_id);
        request_store.insert(slot.slot, request_id);
    }

    info!("Starts to subscribe to {}", beacon_url_head_event);
    let mut stream: mev_share_sse::client::EventStream<HeadEvent> =
        client.subscribe(&beacon_url_head_event).await?;

    while let Some(event) = stream.try_next().await? {
        let slot = event.slot;
        info!("Head Slot: {:?}", slot);
        let epoch = slot / EPOCH_SLOTS;
        let next_slot = slot + 1;

        if request_store.contains_key(&next_slot) {
            info!("Submitting transaction for next slot: {:?}", next_slot);
            let account_nonce = provider.get_transaction_count(signer.address()).await?;
            let data = http_client
                .submit_transaction(
                    *request_store.get(&next_slot).unwrap(),
                    account_nonce,
                    chain_id,
                )
                .await?;
            info!("Transaction submitted: {:?}", data);
        }

        if event.epoch_transition {
            info!("Epoch changed to: {:?}, querying gateway for available slots..", epoch);
            let mut slots = http_client.slots().await?;
            let head_slot = beacon_client.get_sync_status().await?.head_slot;
            info!("Head Slot: {:?}, filering older slots out of {} slots", head_slot, slots.len());
            slots.retain(|slot| slot.slot > head_slot);
            info!("Available slots: {:?}", slots.len());

            for slot in slots {
                info!("Reserving blockspace for slot: {:?}", slot.slot);
                let request_id = http_client.reserve_blockspace(slot.slot).await?;
                info!("Request ID: {:?}", request_id);
                request_store.insert(slot.slot, request_id);
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
struct HttpClient {
    http: reqwest::Client,
    endpoint: Url,
    signer: PrivateKeySigner,
    wallet: EthereumWallet,
}

impl HttpClient {
    fn new(endpoint: Url, signer: PrivateKeySigner) -> Self {
        let wallet = EthereumWallet::from(signer.clone());
        Self { http: reqwest::Client::new(), endpoint, signer, wallet }
    }

    async fn slots(&self) -> eyre::Result<Vec<SlotInfo>> {
        let path = format!("commitments/v0/slots");
        let target = self.endpoint.join(&path)?;
        let result: Vec<SlotInfo> = self.http.get(target).send().await?.json().await?;
        Ok(result)
    }

    async fn reserve_blockspace(&self, slot: u64) -> eyre::Result<Uuid> {
        let path = format!("commitments/v0/preconf_fee");
        let target = self.endpoint.join(&path)?;
        let response = self.http.post(target).json(&slot).send().await?;
        let bytes = response.bytes().await?;
        let preconf_fee: PreconfFeeResponse = serde_json::from_slice(&bytes)?;
        info!("Preconf Fee: {:?}", preconf_fee);

        let gas_limit = 21_000;
        let blob_count = 1;
        let fee = preconf_fee.gas_fee * (gas_limit as u128)
            + preconf_fee.blob_gas_fee * ((blob_count * DATA_GAS_PER_BLOB) as u128);
        let fee = U256::from(fee / 2);

        let blockspace_data = BlockspaceAllocation {
            target_slot: slot,
            deposit: fee,
            tip: fee,
            gas_limit,
            blob_count: blob_count.try_into().unwrap(),
        };
        let signature =
            hex::encode(self.signer.sign_hash(&blockspace_data.digest()).await.unwrap().as_bytes());
        let path = format!("commitments/v0/reserve_blockspace");
        let target = self.endpoint.join(&path)?;
        let result = self
            .http
            .post(target)
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("{}:0x{}", self.signer.address(), signature))
            .json(&blockspace_data)
            .send()
            .await?;
        let bytes = result.bytes().await?;
        let request_id: Uuid = serde_json::from_slice(&bytes)?;
        Ok(request_id)
    }

    async fn submit_transaction(
        &self,
        request_id: Uuid,
        nonce: u64,
        chain_id: u64,
    ) -> eyre::Result<PreconfResponseData> {
        let path = format!("commitments/v0/submit_transaction");
        let target = self.endpoint.join(&path)?;

        let eth_transfer_tx = TransactionRequest::default()
            .with_from(self.signer.address())
            .with_chain_id(chain_id)
            .with_value(U256::from(1000))
            .with_gas_limit(21_000)
            .with_to(self.signer.address())
            .with_max_fee_per_gas(1000000010)
            .with_max_priority_fee_per_gas(1000000000)
            .with_nonce(nonce)
            .build(&self.wallet)
            .await?;

        let request = SubmitTransactionRequest { request_id, transaction: eth_transfer_tx };
        let signature =
            hex::encode(self.signer.sign_hash(&request.digest()).await.unwrap().as_bytes());

        let result = self
            .http
            .post(target)
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{signature}"))
            .json(&request)
            .send()
            .await?;
        let bytes = result.bytes().await?;
        let response: PreconfResponse = serde_json::from_slice(&bytes)?;
        Ok(response.data)
    }
}
