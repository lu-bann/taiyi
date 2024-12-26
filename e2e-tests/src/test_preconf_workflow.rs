use std::str::FromStr;

use alloy_primitives::{Address, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use taiyi_primitives::{PreconfResponse, SubmitTransactionRequest};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    constant::{PRECONFER_BLS_PK, SIGNER_PRIVATE},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        get_available_slot, get_constraints_from_relay, get_estimate_fee, health_check,
        send_reserve_blockspace_request, send_submit_transaction_request, setup_env,
        wati_until_deadline_of_slot,
    },
};

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

#[tokio::test]
async fn test_estimate_fee() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let available_slot = get_available_slot(&config.taiyi_url()).await?;

    let target_slot = available_slot.first().unwrap().slot;

    let estimate_fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    info!("estimate_fee: {:?}", estimate_fee);
    taiyi_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_health_check() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let health_check = health_check(&config.taiyi_url()).await?;

    info!("health_check: {:?}", health_check);
    taiyi_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_commitment_apis() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    {
        // Deposit into the escrow contract
        let signer: PrivateKeySigner = SIGNER_PRIVATE.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&config.execution_url)
            .await?;

        let contract_address: Address = "0xA791D59427B2b7063050187769AC871B497F4b3C".parse()?;
        let taiyi_escrow = TaiyiEscrow::new(contract_address, provider.clone());

        // check if contract exists
        let code = provider.get_code_at(contract_address).await?;
        info!("Contract code: {:?}", code);
        assert!(code.len() > 2);

        let nonce = provider.get_transaction_count(signer.address()).await?;
        info!("Nonce: {:?}", nonce);

        // Call deposit function
        let tx = taiyi_escrow.deposit().value(U256::from(100_000)).into_transaction_request();
        let pending_tx = provider.send_transaction(tx).await?;
        info!("Transaction sent: {:?}", pending_tx.tx_hash());
        // Wait for transaction to be mined
        let receipt = pending_tx.get_receipt().await?;
        info!("Transaction mined in block: {:?}", receipt.block_number.unwrap());

        let nonce = provider.get_transaction_count(signer.address()).await?;
        info!("Nonce: {:?}", nonce);

        // sleep for a while to make sure the transaction is mined
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
        info!("fetching balance");
        let balance = taiyi_escrow.balanceOf(signer.address()).call().await?;
        assert_eq!(balance._0, U256::from(100_000));
    }

    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(SIGNER_PRIVATE, target_slot, fee.fee).await;

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);
    let request_id = serde_json::from_slice::<Uuid>(&body)?;
    assert_eq!(status, 200);

    // Submit transaction
    // Generate request and signature
    let (request, signature) =
        generate_submit_transaction_request(SIGNER_PRIVATE, request_id, &config.execution_url)
            .await;

    let res =
        send_submit_transaction_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("submit transaction response: {:?}", body);
    let preconf_response: PreconfResponse = serde_json::from_slice(&body)?;
    assert_eq!(status, 200);
    assert_eq!(preconf_response.data.request_id, request_id);
    // TODO: verify the commitment signature with gateway pub key

    wati_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;

    assert_eq!(constraints.len(), 1);

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;

    let tx_ret = message.decoded_tx().unwrap().first().unwrap().clone();

    assert_eq!(
        message.pubkey,
        BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
    );

    assert_eq!(message.slot, target_slot);

    assert_eq!(tx_ret, request.transaction);

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_reserve_blockspace_invalid_insufficient_balance() -> eyre::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_reserve_blockspace_invalid_no_balance() -> eyre::Result<()> {
    Ok(())
}
