use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::U256;
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use taiyi_underwriter::clients::execution_client::ExecutionClient;

#[tokio::test]
async fn test_gas_used() -> eyre::Result<()> {
    let anvil = alloy_node_bindings::Anvil::new().block_time(1).chain_id(0).spawn();
    let rpc_url = anvil.endpoint();
    let sender = anvil.addresses().first().unwrap();
    let receiver = anvil.addresses().last().unwrap();
    let client = ExecutionClient::new(rpc_url.parse().unwrap());
    let sender_pk = anvil.keys().first().unwrap();
    let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
    let wallet = EthereumWallet::from(signer.clone());

    let tx = TransactionRequest::default()
        .with_from(*sender)
        .with_to(*receiver)
        .with_value(U256::from(100))
        .with_nonce(0)
        .with_gas_limit(30_000)
        .with_max_fee_per_gas(1)
        .with_max_priority_fee_per_gas(1)
        .with_chain_id(anvil.chain_id())
        .build(&wallet)
        .await?;

    let gas_used = client.gas_used(tx).await?;
    assert_eq!(gas_used, 21000);
    Ok(())
}
