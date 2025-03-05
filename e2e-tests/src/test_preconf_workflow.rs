use std::str::FromStr;

use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use serde::de;
use taiyi_primitives::{PreconfResponse, SubmitTransactionRequest};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    constant::{PRECONFER_BLS_PK, PRECONFER_ECDSA_SK},
    contract_call::{revert_call, taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        generate_type_a_request, get_available_slot, get_constraints_from_relay, get_preconf_fee,
        health_check, new_account, send_reserve_blockspace_request,
        send_submit_transaction_request, send_type_a_request, setup_env,
        wati_until_deadline_of_slot, ErrorResponse,
    },
};

#[tokio::test]
async fn test_preconf_fee() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    let preconf_fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;
    info!("preconf_fee: {:?}", preconf_fee);

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
async fn test_type_b_preconf_request() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_builtin(&config.execution_url)
        .await?;

    // Deposit 1ether to TaiyiCore
    taiyi_deposit(provider.clone(), 1_000_000_000_000_000).await?;

    let balance = taiyi_balance(provider.clone(), signer.address()).await?;
    assert_eq!(balance, U256::from(1_000_000_000_000_000u64));

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee).await;

    info!("Submitting request for target slot: {:?}", target_slot);

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);

    let request_id = serde_json::from_slice::<Uuid>(&body)?;
    assert_eq!(status, 200);

    // Submit transaction
    // Generate request and signature
    let transaction = generate_tx(&config.execution_url, PRECONFER_ECDSA_SK).await.unwrap();
    let (request, signature) =
        generate_submit_transaction_request(signer.clone(), transaction.clone(), request_id).await;

    let res =
        send_submit_transaction_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    assert_eq!(status, 200);
    let body = res.bytes().await?;
    info!("submit transaction response: {:?}", body);
    let preconf_response: PreconfResponse = serde_json::from_slice(&body)?;
    assert_eq!(preconf_response.data.request_id, request_id);

    // TODO: verify the commitment signature with gateway pub key

    wati_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }
    assert!(txs.contains(&transaction));

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;

    let user_tx = txs.get(1).unwrap();

    // TODO: check transaction inclusion in the block

    assert_eq!(
        message.pubkey,
        BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
    );

    assert_eq!(message.slot, target_slot);

    assert_eq!(*user_tx, request.transaction);

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

    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 100000, 0, fee).await;

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

    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 100000, 0, fee).await;

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

#[tokio::test]
async fn test_exhaust_is_called_for_requests_without_preconf_txs() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_builtin(&config.execution_url)
        .await?;

    // Deposit 1ether to TaiyiCore
    taiyi_deposit(provider.clone(), 1_000_000_000_000_000).await?;
    let balance = taiyi_balance(provider.clone(), signer.address()).await?;
    assert_eq!(balance, U256::from(1_000_000_000_000_000u64));
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot + 5;
    info!("Target slot: {:?}", target_slot);

    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee).await;

    // Reserve blockspace
    let res =
        send_reserve_blockspace_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    assert_eq!(status, 200);

    wati_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }

    assert_eq!(txs.len(), 1);

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;
    assert_eq!(message.slot, target_slot);

    let exhaust_tx = txs.get(0).unwrap();
    assert_eq!(exhaust_tx.to().unwrap(), config.taiyi_core);

    // TODO: check transaction inclusion in the block

    // TODO: check user balance is deducted by the deposit amount
    // let balance_after = taiyi_balance(provider, signer.address()).await?;
    // assert_eq!(balance_after, balance - request.deposit);

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}

// ~~~~~~~ Type A preconf request ~~~~~~~

#[tokio::test]
async fn test_type_a_preconf_request() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_type_a_request(PRECONFER_ECDSA_SK, target_slot, &config.execution_url, fee)
            .await?;

    info!("Submitting request for target slot: {:?}", target_slot);
    let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("submit Type A request response: {:?}", body);
    assert_eq!(status, 200);
    let preconf_response: PreconfResponse = serde_json::from_slice(&body)?;
    info!("preconf_response: {:?}", preconf_response);

    wati_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }

    // check if constraints contains our transaction
    assert!(txs.contains(&request.preconf_transaction));
    assert!(txs.contains(&request.tip_transaction));

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}
