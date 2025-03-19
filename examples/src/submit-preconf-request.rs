use alloy_primitives::{PrimitiveSignature, U256};
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use reqwest::Url;
use taiyi_primitives::{BlockspaceAllocation, PreconfRequestTypeB, SlotInfo};
const PRECONF_REQUEST_PATH: &str = "/commitments/v1/preconf_request";
#[tokio::main]
async fn main() -> eyre::Result<()> {
    let taiyi_url = std::env::var("TAIYI_PRECONFER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5656".to_string());
    let el_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let signer_private = std::env::var("PRIVATE_KEY").expect("Input private key");
    let signer: PrivateKeySigner = signer_private.parse().unwrap();
    let provider = ProviderBuilder::new().with_recommended_fillers().on_builtin(&el_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let client = reqwest::Client::new();
    let res = client.get(&format!("{}/commitments/v1/slots", taiyi_url)).send().await?;
    let res_b = res.bytes().await?;
    let available_slots = serde_json::from_slice::<Vec<SlotInfo>>(&res_b)?;
    println!("available_slots: {:?}", available_slots);
    if available_slots.is_empty() {
        println!("No available slot");
        return Ok(());
    }
    let target_slot = available_slots.first().unwrap().slot;
    println!("sender: {:?} target_slot: {:?}", sender, target_slot);
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

    let tx_hash = transaction.tx_hash();
    println!("tx_hash: {:?}", tx_hash);

    let preconf_request = PreconfRequestTypeB {
        allocation: BlockspaceAllocation::default(),
        alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
        transaction: Some(transaction.clone()),
        signer: sender,
    };
    let request_endpoint = Url::parse(&taiyi_url).unwrap().join(PRECONF_REQUEST_PATH).unwrap();
    let response =
        reqwest::Client::new().post(request_endpoint.clone()).json(&preconf_request).send().await?;

    let res_body = response.bytes().await?;

    println!("res_body: {:?}", res_body);

    Ok(())
}
