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
    constant::{PRECONFER_BLS_PK, PRECONFER_ECDSA_SK},
    contract_call::{revert_call, taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        get_available_slot, get_constraints_from_relay, get_estimate_fee, health_check,
        new_account, send_reserve_blockspace_request, send_submit_transaction_request, setup_env,
        wati_until_deadline_of_slot, ErrorResponse,
    },
};

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
    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_builtin(&config.execution_url)
        .await?;
    taiyi_deposit(provider.clone(), 100_000).await?;
    let balance = taiyi_balance(provider, signer.address()).await?;
    assert_eq!(balance, U256::from(100_000));
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, fee.fee).await;

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);
    let request_id = serde_json::from_slice::<Uuid>(&body)?;
    assert_eq!(status, 200);

    let transaction = generate_tx(&config.execution_url, PRECONFER_ECDSA_SK).await.unwrap();

    // Submit transaction
    // Generate request and signature
    let (request, signature) =
        generate_submit_transaction_request(signer.clone(), transaction, request_id).await;

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
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&config.execution_url)
        .await?;
    let balance = taiyi_balance(provider.clone(), signer.address()).await?;
    assert_eq!(balance, U256::from(0));
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 100000, fee.fee).await;

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);
    let response = serde_json::from_slice::<ErrorResponse>(&body)?;
    assert_eq!(status, 400);
    assert!(response.message.contains("InsufficientEscrowBalance"));
    taiyi_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_reserve_blockspace_invalid_reverter() -> eyre::Result<()> {
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&config.execution_url)
        .await?;
    taiyi_deposit(provider.clone(), 100_000).await?;
    let balance = taiyi_balance(provider.clone(), signer.address()).await?;
    assert_eq!(balance, U256::from(100_000));
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 100000, fee.fee).await;

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);
    let request_id = serde_json::from_slice::<Uuid>(&body)?;
    assert_eq!(status, 200);

    let tx = revert_call(provider, &wallet).await?;
    // Submit transaction
    // Generate request and signature
    let (request, signature) =
        generate_submit_transaction_request(signer.clone(), tx, request_id).await;

    let res =
        send_submit_transaction_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("submit transaction response: {:?}", body);
    let preconf_response: PreconfResponse = serde_json::from_slice(&body)?;
    // CUrrently revert tx is not rejected.
    assert_eq!(status, 200);
    assert_eq!(preconf_response.data.request_id, request_id);
    taiyi_handle.abort();
    Ok(())
}
