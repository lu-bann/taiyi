#![allow(unused_imports)]
#![allow(unused_variables)]

use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use reth_primitives::{
    Transaction, TransactionKind, TransactionSigned, TransactionSignedEcRecovered, TxEip1559, U256,
};
use taiyi_primitives::{AvailableSlotResponse, PreconfRequest, TipTransaction};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let taiyi_url =
        std::env::var("TAIYI_URL").unwrap_or_else(|_| "http://127.0.0.1:18550".to_string());
    let el_url = std::env::var("EL_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let signer_private = std::env::var("PRIVATE_KEY").expect("Input private key");
    let signer: PrivateKeySigner = signer_private.parse().unwrap();
    let provider = ProviderBuilder::new().with_recommended_fillers().on_builtin(&el_url).await?;

    let client = reqwest::Client::new();
    let res = client.get(&format!("{}/commitments/v1/slots", taiyi_url)).send().await?;
    let res_b = res.bytes().await?;
    println!("res: {:?}", res_b);
    let available_slot = serde_json::from_slice::<AvailableSlotResponse>(&res_b)?;
    if available_slot.available_slots.is_empty() {
        println!("No available slot");
        return Ok(());
    }
    let target_slot = available_slot.available_slots.last().expect("last").slot;
    println!("target_slot: {:?}", available_slot);

    let estimate = provider.estimate_eip1559_fees(None).await?;
    let nonce = provider.get_transaction_count(signer.address()).await?;

    let tx: Transaction = Transaction::Eip1559(TxEip1559 {
        chain_id: 7014190335,
        nonce,
        max_priority_fee_per_gas: estimate.max_priority_fee_per_gas,
        max_fee_per_gas: estimate.max_fee_per_gas,
        gas_limit: 220000,
        to: TransactionKind::Call("0xc998d0300e83d2Bf0eD9abB2A62D25A368adb8ED".parse().unwrap()),
        value: U256::from(10),
        input: Default::default(),
        access_list: Default::default(),
    });
    let sig: [u8; 65] = signer.sign_hash_sync(&tx.signature_hash())?.into();
    let sig: reth_primitives::Signature = reth_primitives::Signature {
        r: U256::try_from_be_slice(&sig[..32]).expect("The slice has at most 32 bytes"),
        s: U256::try_from_be_slice(&sig[32..64]).expect("The slice has at most 32 bytes"),
        odd_y_parity: sig[64] != 0,
    };
    let tx = TransactionSignedEcRecovered::from_signed_transaction(
        TransactionSigned::from_transaction_and_signature(tx, sig),
        signer.address(),
    );

    let tx_b = serde_json::to_vec(&tx.into_signed()).unwrap();
    // let preconf_request = PreconfRequest {
    //     preconf_tx: Some(tx_b),
    //     tip_tx: TipTransaction::new(
    //         Default::default(),
    //         signer.address(),
    //         Default::default(),
    //         Default::default(),
    //         Default::default(),
    //         Default::default(),
    //         U256::from(target_slot),
    //     ),
    //     tip_tx_signature: Signature::,
    //     preconfer_signature: Default::default(),
    // };
    // let res = client
    //     .post(&format!("{}/commitments/v1/preconf_request", taiyi_url))
    //     .json(&preconf_request)
    //     .send()
    //     .await?;
    // let res_body = res.text().await?;
    // println!("res: {}", res_body);
    Ok(())
}
