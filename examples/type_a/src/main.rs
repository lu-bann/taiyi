#![allow(clippy::unwrap_used)]
use alloy_eips::{self, eip4844::DATA_GAS_PER_BLOB};
use alloy_primitives::{Address, U256};
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use beacon_api_client::mainnet::Client as BeaconClient;
use reqwest::Url;
use taiyi_primitives::{
    PreconfFeeResponse, PreconfResponseData, SlotInfo, SubmitTypeATransactionRequest,
};
use taiyi_underwriter::{AVAILABLE_SLOT_PATH, PRECONF_FEE_PATH, SUBMIT_TYPEA_TRANSACTION_PATH};
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt().init();

    let underwriter_url =
        std::env::var("UNDERWRITER_URL").expect("UNDERWRITER_URL must be set").parse::<Url>()?;
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let execution_client_url =
        std::env::var("EXECUTION_CLIENT_URL").expect("EXECUTION_CLIENT_URL must be set");
    let beacon_client_url =
        std::env::var("BEACON_CLIENT_URL").expect("BEACON_CLIENT_URL must be set");
    let underwriter_address = std::env::var("UNDERWRITER_ADDRESS")
        .expect("UNDERWRITER_ADDRESS must be set")
        .parse::<Address>()?;

    let signer: PrivateKeySigner = private_key.parse()?;
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(execution_client_url.parse()?);
    let chain_id = provider.get_chain_id().await?;

    let beacon_client = BeaconClient::new(beacon_client_url.parse::<Url>()?);

    // Step-1: Pick a slot for preconfirmation
    let client = reqwest::Client::new();
    let target = underwriter_url.join(AVAILABLE_SLOT_PATH)?;
    let response = client.get(target).send().await?;
    let bytes = response.bytes().await?;
    let result: Vec<SlotInfo> = serde_json::from_slice(&bytes)?;
    let mut slots = result.iter().map(|slot| slot.slot).collect::<Vec<_>>();
    let head_slot = beacon_client.get_sync_status().await?.head_slot;
    info!("Head Slot: {:?}, filering older slots out of {} slots", head_slot, slots.len());
    slots.retain(|slot| *slot > head_slot);
    let target_slot = slots.first().unwrap();
    info!("Target Slot: {:?}", target_slot);

    // Step-2: Query preconf fee for the target slot
    let target = underwriter_url.join(PRECONF_FEE_PATH)?;
    let result = client.post(target).json(&target_slot).send().await?;
    let bytes = result.bytes().await?;
    let preconf_fee: PreconfFeeResponse = serde_json::from_slice(&bytes)?;

    // Step-3: Send preconf transactions
    let account_nonce = provider.get_transaction_count(signer.address()).await?;
    let fees = provider.estimate_eip1559_fees(None).await?;
    // Sends preconf fees to the underwriter
    let tip_transaction = TransactionRequest::default()
        .with_from(signer.address())
        .with_to(underwriter_address)
        .with_nonce(account_nonce)
        .with_gas_limit(21_000)
        .with_max_fee_per_gas(10 * fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(10 * fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id);

    let preconf_tx = TransactionRequest::default()
        .with_from(signer.address())
        .with_to(signer.address())
        .with_nonce(account_nonce + 1)
        .with_gas_limit(21_000)
        .with_max_fee_per_gas(10 * fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(10 * fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .with_value(U256::from(1000))
        .build(&wallet)
        .await?;

    let gas_limit = 21_000 * 2;
    let blob_count = 0;
    let preconf_tip = preconf_fee.gas_fee * (gas_limit) as u128
        + preconf_fee.blob_gas_fee * ((blob_count * DATA_GAS_PER_BLOB) as u128);

    let tip_transaction =
        tip_transaction.with_value(U256::from(preconf_tip)).build(&wallet).await?;

    info!("Tip tx Hash: {:?}", tip_transaction.tx_hash());
    info!("Preconf Transaction Hash: {:?}", preconf_tx.tx_hash());

    let request =
        SubmitTypeATransactionRequest::new(vec![preconf_tx], tip_transaction, *target_slot);
    let x_luban_sig_header =
        format!("0x{}", hex::encode(signer.sign_hash(&request.digest()).await?.as_bytes()));

    let target = underwriter_url.join(SUBMIT_TYPEA_TRANSACTION_PATH)?;
    let result = client
        .post(target)
        .header("content-type", "application/json")
        .header("x-luban-signature", x_luban_sig_header)
        .json(&request)
        .send()
        .await?;
    let bytes = result.bytes().await?;
    let data: PreconfResponseData = serde_json::from_slice(&bytes)?;
    let commitment = hex::encode(data.commitment.unwrap().as_bytes());
    info!("Commitment: {:?}", format!("0x{}", commitment));

    Ok(())
}
