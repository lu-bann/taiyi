#![allow(unused_imports)]
#![allow(unused_variables)]

use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use reth_primitives::{Transaction, TransactionSigned, TransactionSignedEcRecovered};
use taiyi_primitives::{AvailableSlotResponse, PreconfRequest, PreconfTx, TipTransaction};

const TAIYI_CORE_ADDRESS: &str = "0xBc158E71537d843616D1fE0cc5e39900bB38cBff"; // taiyi core contract address for Helder
const TAIYI_PRECONFER_ADDRESS: &str = "0xbC37A63E213a791c944a7EA104e67FB5B4b3DF07"; // taiyi preconfer contract address for Helder

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let taiyi_url = std::env::var("TAIYI_PRECONFER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5656".to_string());
    let el_url = std::env::var("EL_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let signer_private = std::env::var("PRIVATE_KEY").expect("Input private key");
    let signer: PrivateKeySigner = signer_private.parse().unwrap();
    let provider = ProviderBuilder::new().with_recommended_fillers().on_builtin(&el_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let client = reqwest::Client::new();
    let preconfer_address: Address = TAIYI_PRECONFER_ADDRESS.parse().unwrap();
    let res = client.get(&format!("{}/commitments/v1/slots", taiyi_url)).send().await?;
    let res_b = res.bytes().await?;
    println!("res: {:?}", res_b);
    let available_slot = serde_json::from_slice::<AvailableSlotResponse>(&res_b)?;
    if available_slot.available_slots.is_empty() {
        println!("No available slot");
        return Ok(());
    }
    println!("available_slot: {:?}", available_slot);
    let target_slot = available_slot.available_slots.last().unwrap().slot;
    println!("target_slot: {:?}", target_slot);
    sol!(
        #[sol(rpc)]
        contract TaiyiCore{
            function getTipNonce(address sender) public view returns (uint256 nonce);
            function getPreconfNonce(address sender) public view returns (uint256 nonce);
        }
    );

    let contract =
        TaiyiCore::TaiyiCoreInstance::new(TAIYI_CORE_ADDRESS.parse().unwrap(), provider.clone());
    let tip_nonce = contract.getTipNonce(sender).call().await?.nonce;
    let preconf_nonce = contract.getPreconfNonce(sender).call().await?.nonce;
    let estimate = provider.estimate_eip1559_fees(None).await?;
    let to_addr: Address = "0x39e7971cF48AAf3222BDe5871d45829e274CD356".parse().unwrap();
    let tip_tx = TipTransaction {
        gas_limit: U256::from(21_000),
        from: sender,
        to: preconfer_address,
        // the user would need to pay pre_pay to preconfer for the preconf request even if it is failed
        pre_pay: U256::from(estimate.max_fee_per_gas * 2_000),
        // the user need to pay after_pay  to preconfer for the preconf request when the tx is successful
        after_pay: U256::from(estimate.max_fee_per_gas * 1_000),
        nonce: tip_nonce,
        target_slot: U256::from(target_slot),
    };
    let tip_hash = tip_tx.tip_tx_hash(U256::from(chain_id));
    let tip_sig = signer.sign_hash_sync(&tip_hash)?;
    let mut preconf_tx = PreconfTx {
        from: sender,
        to: to_addr,
        value: U256::from(10000000000000000u64),
        call_data: Default::default(),
        call_gas_limit: U256::from(1000000),
        nonce: preconf_nonce,
        signature: Default::default(),
        permit_data: Default::default(),
    };
    let preconf_hash = preconf_tx.hash();
    let preconf_sig: Vec<u8> = signer.sign_hash_sync(&preconf_hash)?.into();
    preconf_tx.signature = Bytes::from(preconf_sig);
    let preconf_request = PreconfRequest {
        tip_tx: tip_tx.into(),
        tip_tx_signature: tip_sig,
        preconf_tx: Some(preconf_tx),
        preconfer_signature: None,
        preconf_req_signature: None,
    };

    let res = client
        .post(&format!("{}/commitments/v1/preconf_request", taiyi_url))
        .json(&preconf_request)
        .send()
        .await?;
    let res_body = res.text().await?;
    println!("res: {}", res_body);
    Ok(())
}
