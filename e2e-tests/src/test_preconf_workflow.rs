use std::str::FromStr;

use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use serde::de;
use taiyi_preconfer::metrics::provider;
use taiyi_primitives::{PreconfResponse, SubmitTransactionRequest};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    constant::{PRECONFER_BLS_PK, PRECONFER_ECDSA_SK},
    contract_call::{revert_call, taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        generate_tx_with_nonce, generate_type_a_request, generate_type_a_request_with_nonce,
        get_available_slot, get_block_from_slot, get_constraints_from_relay, get_preconf_fee,
        health_check, new_account, send_reserve_blockspace_request,
        send_submit_transaction_request, send_type_a_request, setup_env, verify_tx_in_block,
        verify_txs_inclusion, wati_until_deadline_of_slot, ErrorResponse,
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
    info!("available_slot: {:?}", available_slot);
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
    let transaction = generate_tx(&config.execution_url, signer.clone()).await.unwrap();
    let (request, signature) =
        generate_submit_transaction_request(signer.clone(), transaction.clone(), request_id).await;

    let res =
        send_submit_transaction_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("submit transaction response: {:?}", body);
    assert_eq!(status, 200);
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

    // Check if there's a payout transaction to the fee recipient
    let fee_recipient = Address::from_str("0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap();
    let mut payout_tx = None;
    for tx in &txs {
        if tx.to().unwrap() == fee_recipient {
            payout_tx = Some(tx.clone());
            break;
        }
    }
    assert!(payout_tx.is_some());

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;

    assert_eq!(
        message.pubkey,
        BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
    );
    assert_eq!(message.slot, target_slot);

    info!("Waiting for slot {} to be available", target_slot);
    wati_until_deadline_of_slot(&config, target_slot + 1).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    assert!(
        verify_tx_in_block(&config.execution_url, block_number, transaction.tx_hash().clone())
            .await
            .is_ok(),
        "tx is not in the block"
    );

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
    if available_slot.is_empty() {
        return Ok(());
    }
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

#[ignore = "TODO: check for exhaust tx"]
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
    let target_slot = available_slot.first().unwrap().slot;
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

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;
    assert_eq!(message.slot, target_slot);

    // TODO: check transaction inclusion in the block

    // TODO: check user balance is deducted by the deposit amount
    // let balance_after = taiyi_balance(provider, signer.address()).await?;
    // assert_eq!(balance_after, balance - request.deposit);

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}

// ============================= Type A preconf request =============================

#[tokio::test]
async fn test_type_a_preconf_request() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_type_a_request(signer, target_slot, &config.execution_url, fee).await?;

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
    assert!(txs.contains(&request.preconf_transaction.first().unwrap()));
    assert!(txs.contains(&request.tip_transaction));

    wati_until_deadline_of_slot(&config, target_slot + 2).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            request.tip_transaction.tx_hash().clone()
        )
        .await
        .is_ok(),
        "tip tx is not in the block"
    );
    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            request.preconf_transaction.first().unwrap().tx_hash().clone()
        )
        .await
        .is_ok(),
        "preconf tx is not in the block"
    );

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_type_a_and_type_b_requests() -> eyre::Result<()> {
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

    let mut nonce = provider.get_transaction_count(signer.address()).await?;
    let mut submitted_txs = Vec::new();

    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let requests_lim = available_slot.len().min(10);
    for (idx, slot) in available_slot.iter().enumerate() {
        if idx >= requests_lim {
            break;
        }
        let target_slot = slot.slot;
        let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

        // Generate request and signature
        let (request, signature) = generate_type_a_request_with_nonce(
            signer.clone(),
            target_slot,
            &config.execution_url,
            fee.clone(),
            nonce,
        )
        .await?;
        nonce += 2;

        let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
        let status = res.status();
        let body = res.bytes().await?;
        info!("submit Type A request response: {:?}", body);
        assert_eq!(status, 200);
        let preconf_response: PreconfResponse = serde_json::from_slice(&body)?;
        info!("preconf_response: {:?}", preconf_response);
        submitted_txs.push(request.tip_transaction.clone());
        submitted_txs.push(request.preconf_transaction.first().unwrap().clone());

        // Generate request and signature
        let (request, signature) =
            generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee).await;

        // Reserve blockspace
        let res = send_reserve_blockspace_request(request.clone(), signature, &config.taiyi_url())
            .await?;
        let status = res.status();
        let body = res.bytes().await?;
        info!("reserve_blockspace response: {:?}", body);

        let request_id = serde_json::from_slice::<Uuid>(&body)?;
        assert_eq!(status, 200);

        let transaction =
            generate_tx_with_nonce(&config.execution_url, signer.clone(), nonce).await.unwrap();
        let (request, signature) =
            generate_submit_transaction_request(signer.clone(), transaction.clone(), request_id)
                .await;

        let res = send_submit_transaction_request(request.clone(), signature, &config.taiyi_url())
            .await?;
        let status = res.status();
        let body = res.bytes().await?;
        info!("submit transaction response: {:?}", body);
        assert_eq!(status, 200);
        submitted_txs.push(transaction);

        nonce += 1;
    }

    wati_until_deadline_of_slot(&config, available_slot.last().unwrap().slot + 1).await?;
    assert!(verify_txs_inclusion(&config.execution_url, submitted_txs).await.is_ok());

    taiyi_handle.abort();
    Ok(())
}
