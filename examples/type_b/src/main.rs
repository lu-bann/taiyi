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
use alloy_sol_types::sol;
use beacon_api_client::mainnet::Client as BeaconClient;
use reqwest::Url;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeResponse, PreconfResponseData, SlotInfo,
    SubmitTransactionRequest,
};
use taiyi_underwriter::{
    AVAILABLE_SLOT_PATH, PRECONF_FEE_PATH, RESERVE_BLOCKSPACE_PATH, SUBMIT_TRANSACTION_PATH,
};
use tracing::info;
use uuid::Uuid;

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

    let underwriter_url =
        std::env::var("UNDERWRITER_URL").expect("UNDERWRITER_URL must be set").parse::<Url>()?;
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let execution_client_url =
        std::env::var("EXECUTION_CLIENT_URL").expect("EXECUTION_CLIENT_URL must be set");
    let beacon_client_url =
        std::env::var("BEACON_CLIENT_URL").expect("BEACON_CLIENT_URL must be set");
    let taiyi_core_address =
        std::env::var("TAIYI_CORE_ADDRESS").expect("TAIYI_CORE_ADDRESS must be set");
    let taiyi_core_address = taiyi_core_address.parse::<Address>()?;
    let underwriter_address = std::env::var("UNDERWRITER_ADDRESS")
        .expect("UNDERWRITER_ADDRESS must be set")
        .parse::<Address>()?;

    let signer: PrivateKeySigner = private_key.parse()?;
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(execution_client_url.parse()?);
    let chain_id = provider.get_chain_id().await?;

    // Step-1: Deposit into TaiyiCore
    //
    // This is required to able to reserve blockspace for the slot.
    let taiyi_escrow = TaiyiEscrow::new(taiyi_core_address, provider.clone());
    let account_nonce = provider.get_transaction_count(signer.address()).await?;
    let fees = provider.estimate_eip1559_fees(None).await?;

    let tx = taiyi_escrow
        .deposit()
        .value(U256::from(1_000_000_000_000_000_000u128)) // 1 ETH
        .into_transaction_request()
        .with_chain_id(chain_id)
        .with_gas_limit(100_000)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_nonce(account_nonce);
    let pending_tx = provider.send_transaction(tx).await?;
    info!("Deposit Transaction sent: {:?}", pending_tx.tx_hash());
    let receipt = pending_tx.get_receipt().await?;
    info!("Deposit Transaction included in block: {:?}", receipt.block_number.unwrap());

    let beacon_client = BeaconClient::new(beacon_client_url.parse::<Url>()?);

    // Step-2: Pick a slot for preconfirmation
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

    // Step-3: Query preconf fee for the target slot
    let target = underwriter_url.join(PRECONF_FEE_PATH)?;
    let result = client.post(target).json(&target_slot).send().await?;
    let bytes = result.bytes().await?;
    let preconf_fee: PreconfFeeResponse = serde_json::from_slice(&bytes)?;

    // Step-4 Send reserve blockspace request for that slot
    // Desired gas limit and blob count
    let gas_limit = 21_000;
    let blob_count = 0;
    let fee = preconf_fee.gas_fee * (gas_limit as u128)
        + preconf_fee.blob_gas_fee * ((blob_count * DATA_GAS_PER_BLOB) as u128);
    let fee = U256::from(fee / 2);
    let blockspace_data = BlockspaceAllocation {
        target_slot: *target_slot,
        sender: signer.address(),
        recipient: underwriter_address,
        deposit: fee,
        tip: fee,
        gas_limit,
        blob_count: blob_count.try_into().unwrap(),
    };
    let x_luban_sig_header = format!(
        "0x{}",
        hex::encode(signer.sign_hash(&blockspace_data.hash(chain_id)).await?.as_bytes())
    );

    let target = underwriter_url.join(RESERVE_BLOCKSPACE_PATH)?;
    let result = client
        .post(target)
        .header("content-type", "application/json")
        .header("x-luban-signature", x_luban_sig_header)
        .json(&blockspace_data)
        .send()
        .await?;
    let bytes = result.bytes().await?;
    let request_id: Uuid = serde_json::from_slice(&bytes)?;
    info!("Request ID: {:?}", request_id);

    // Step-5: Send your transaction for the reserved slot
    // You can send the transaction whenever you want, but it is recommended to send it just before the slot starts
    loop {
        let current_slot = beacon_client.get_sync_status().await?.head_slot;
        info!("Current Slot: {:?}", current_slot);
        if current_slot + 1 == *target_slot {
            break;
        }
    }

    let account_nonce = provider.get_transaction_count(signer.address()).await?;
    let target = underwriter_url.join(SUBMIT_TRANSACTION_PATH)?;

    let preconf_tx = TransactionRequest::default()
        .with_from(signer.address())
        .with_to(underwriter_address)
        .with_chain_id(chain_id)
        .with_value(U256::from(1000))
        .with_gas_limit(21_000)
        .with_max_fee_per_gas(10 * fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_nonce(account_nonce)
        .build(&wallet)
        .await?;
    info!("Transaction hash: {:?}", preconf_tx.tx_hash());
    let request = SubmitTransactionRequest { request_id, transaction: preconf_tx };
    let x_luban_sig_header =
        format!("0x{}", hex::encode(signer.sign_hash(&request.digest()).await.unwrap().as_bytes()));
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
