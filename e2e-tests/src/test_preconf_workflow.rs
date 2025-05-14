use std::str::FromStr;

use alloy_consensus::{constants::ETH_TO_WEI, Transaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall, SolValue};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use reqwest::Url;
use serde::de;
use taiyi_primitives::{
    PreconfFeeResponse, PreconfRequestTypeA, PreconfResponseData, SubmitTransactionRequest,
};
use taiyi_underwriter::TaiyiCore;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    constant::{UNDERWRITER_ADDRESS, UNDERWRITER_BLS_PK, UNDERWRITER_ECDSA_SK},
    contract_call::{revert_call, taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        generate_tx_with_nonce, generate_type_a_request, generate_type_a_request_with_nonce,
        get_available_slot, get_block_from_slot, get_constraints_from_relay, get_preconf_fee,
        health_check, new_account, send_reserve_blockspace_request,
        send_submit_transaction_request, send_type_a_request, setup_env, verify_tx_in_block,
        verify_txs_inclusion, wait_until_deadline_of_slot, ErrorResponse,
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

    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_health_check() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let health_check = health_check(&config.taiyi_url()).await?;
    info!("health_check: {:?}", health_check);

    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_type_b_preconf_request() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(Url::from_str(&config.execution_url)?);

    info!("type b preconf request");
    let chain_id = provider.get_chain_id().await?;

    // Deposit 1ether to TaiyiCore
    taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config).await?;

    let balance = taiyi_balance(provider.clone(), signer.address(), &config).await?;
    assert_eq!(balance, U256::from(5 * ETH_TO_WEI));

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    info!("available_slot: {:?}", available_slot);
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (blockspace_request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee, chain_id)
            .await;

    info!("Submitting request for target slot: {:?}", target_slot);

    // Reserve blockspace
    let res =
        send_reserve_blockspace_request(blockspace_request.clone(), signature, &config.taiyi_url())
            .await?;
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
    let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
    assert_eq!(preconf_response.request_id, request_id);

    let commitment = preconf_response.commitment.unwrap();
    let mut tx_bytes = Vec::new();
    transaction.clone().encode_2718(&mut tx_bytes);
    let raw_tx = format!("0x{}", hex::encode(&tx_bytes));
    let data =
        keccak256((blockspace_request.hash(chain_id), raw_tx.as_bytes()).abi_encode_packed());
    let signer = commitment.recover_address_from_prehash(&data).unwrap();
    assert!(signer == Address::from_str(UNDERWRITER_ADDRESS).unwrap());

    wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }
    assert!(txs.contains(&transaction));

    let fee_recipient = Address::from_str("0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap();
    let sponsor_eth_selector = TaiyiCore::sponsorEthBatchCall::SELECTOR;
    let get_tip_selector = TaiyiCore::getTipCall::SELECTOR;
    let mut sponsor_tx = None;
    let mut get_tip_tx = None;
    let mut payout_tx = None;
    for tx in &txs {
        if tx.kind().is_call() {
            let selector = tx.input().get(0..4).unwrap_or_default();
            if selector == sponsor_eth_selector {
                sponsor_tx = Some(tx.clone());
            } else if selector == get_tip_selector {
                get_tip_tx = Some(tx.clone());
            }
        }

        if payout_tx.is_none() && tx.to().unwrap() == fee_recipient {
            payout_tx = Some(tx.clone());
        }
    }
    assert!(sponsor_tx.is_some());
    assert!(get_tip_tx.is_some());
    assert!(payout_tx.is_some());

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;

    assert_eq!(
        message.pubkey,
        BlsPublicKey::try_from(hex::decode(UNDERWRITER_BLS_PK).unwrap().as_slice()).unwrap()
    );
    assert_eq!(message.slot, target_slot);

    info!("Waiting for slot {} to be available", target_slot);

    wait_until_deadline_of_slot(&config, target_slot + 1).await?;

    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    assert!(
        verify_tx_in_block(&config.execution_url, block_number, transaction.tx_hash().clone())
            .await
            .is_ok(),
        "tx is not in the block"
    );

    // Optionally, cleanup when done
    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_reserve_blockspace_invalid_insufficient_balance() -> eyre::Result<()> {
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .on_http(Url::from_str(&config.execution_url)?);
    let chain_id = provider.get_chain_id().await?;

    let balance = taiyi_balance(provider.clone(), signer.address(), &config).await?;
    assert_eq!(balance, U256::from(0));
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 100000, 0, fee, chain_id)
            .await;

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);
    let response = serde_json::from_slice::<ErrorResponse>(&body)?;
    assert_eq!(status, 400);
    assert!(response.message.contains("InsufficientEscrowBalance"));
    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_reserve_blockspace_invalid_reverter() -> eyre::Result<()> {
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .on_http(Url::from_str(&config.execution_url)?);
    let chain_id = provider.get_chain_id().await?;

    taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config).await?;
    let balance = taiyi_balance(provider.clone(), signer.address(), &config).await?;
    assert_eq!(balance, U256::from(5 * ETH_TO_WEI));

    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    if available_slot.is_empty() {
        return Ok(());
    }
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 100000, 0, fee, chain_id)
            .await;

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
    let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
    // CUrrently revert tx is not rejected.
    assert_eq!(status, 200);
    assert_eq!(preconf_response.request_id, request_id);
    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_exhaust_is_called_for_requests_without_preconf_txs() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(Url::from_str(&config.execution_url)?);
    let chain_id = provider.get_chain_id().await?;

    // Deposit 1ether to TaiyiCore
    taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config).await?;
    let balance = taiyi_balance(provider.clone(), signer.address(), &config).await?;
    assert_eq!(balance, U256::from(5 * ETH_TO_WEI));
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;
    info!("Target slot: {:?}", target_slot);

    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee, chain_id)
            .await;

    // Reserve blockspace
    let res =
        send_reserve_blockspace_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    assert_eq!(status, 200);

    wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }

    let exhaust_func_selector = TaiyiCore::exhaustCall::SELECTOR;

    let mut exhaust_tx = None;
    for tx in &txs {
        if tx.kind().is_call() {
            let selector = tx.input().get(0..4).unwrap();
            if selector == exhaust_func_selector {
                exhaust_tx = Some(tx.clone());
                break;
            }
        }
    }
    assert!(exhaust_tx.is_some());

    wait_until_deadline_of_slot(&config, target_slot + 1).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            exhaust_tx.unwrap().tx_hash().clone()
        )
        .await
        .is_ok(),
        "exhaust tx is not in the block"
    );

    let balance_after = taiyi_balance(provider, signer.address(), &config).await?;
    assert_eq!(balance_after, balance - request.deposit);

    // Optionally, cleanup when done
    drop(taiyi_handle);
    Ok(())
}

// ============================= Type A preconf request =============================

#[tokio::test]
async fn test_type_a_preconf_request() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(Url::from_str(&config.execution_url)?);
    let chain_id = provider.get_chain_id().await?;

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_type_a_request(signer.clone(), target_slot, &config.execution_url, fee.clone())
            .await?;

    info!("Submitting request for target slot: {:?}", target_slot);
    info!("tip tx: {:?}", request.tip_transaction.tx_hash());
    for tx in &request.preconf_transaction {
        info!("preconf tx: {:?}", tx.tx_hash());
    }
    let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("submit Type A request response: {:?}", body);
    assert_eq!(status, 200);
    let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
    info!("preconf_response: {:?}", preconf_response);

    let commitment = preconf_response.commitment.unwrap();
    let type_a = PreconfRequestTypeA {
        tip_transaction: request.tip_transaction.clone(),
        preconf_tx: request.preconf_transaction.clone(),
        target_slot: request.target_slot,
        sequence_number: preconf_response.sequence_num,
        signer: signer.address(),
        preconf_fee: PreconfFeeResponse::default(),
    };
    let data = type_a.digest(chain_id);
    let signer = commitment.recover_address_from_prehash(&data).unwrap();
    assert!(signer == Address::from_str(UNDERWRITER_ADDRESS).unwrap());

    wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }

    // check if constraints contains our transaction
    assert!(
        txs.contains(&request.preconf_transaction.first().unwrap()),
        "preconf tx {:?} is not in the constraints",
        request.preconf_transaction.first().unwrap().tx_hash()
    );
    assert!(
        txs.contains(&request.tip_transaction),
        "tip tx {:?} is not in the constraints",
        request.tip_transaction.tx_hash()
    );

    wait_until_deadline_of_slot(&config, target_slot + 1).await?;
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
    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_send_multiple_type_a_preconf_for_the_same_slot() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    // Create two different users
    let user1 = new_account(&config).await?;
    let user2 = new_account(&config).await?;

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate first request and signature from user1
    let (request1, signature1) =
        generate_type_a_request(user1.clone(), target_slot, &config.execution_url, fee.clone())
            .await?;

    info!("Submitting first request from user1 for target slot: {:?}", target_slot);
    info!("user1 tip tx: {:?}", request1.tip_transaction.tx_hash());
    for tx in &request1.preconf_transaction {
        info!("user1 preconf tx: {:?}", tx.tx_hash());
    }
    let res1 = send_type_a_request(request1.clone(), signature1, &config.taiyi_url()).await?;
    let status1 = res1.status();
    let body1 = res1.bytes().await?;
    info!("First Type A request response: {:?}", body1);
    assert_eq!(status1, 200);
    let preconf_response1: PreconfResponseData = serde_json::from_slice(&body1)?;
    info!("First preconf_response: {:?}", preconf_response1);

    // Generate second request and signature from user2 for the same slot
    let (request2, signature2) =
        generate_type_a_request(user2.clone(), target_slot, &config.execution_url, fee).await?;

    info!("Submitting second request from user2 for target slot: {:?}", target_slot);
    info!("user2 tip tx: {:?}", request2.tip_transaction.tx_hash());
    for tx in &request2.preconf_transaction {
        info!("user2 preconf tx: {:?}", tx.tx_hash());
    }
    let res2 = send_type_a_request(request2.clone(), signature2, &config.taiyi_url()).await?;
    let status2 = res2.status();
    let body2 = res2.bytes().await?;
    info!("Second Type A request response: {:?}", body2);
    assert_eq!(status2, 200);

    // Verify only the first request's transactions are included in the constraints
    wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }

    // Check if constraints contains only user1's transactions
    assert!(
        txs.contains(&request1.preconf_transaction.first().unwrap()),
        "User1's preconf tx {:?} is in the constraints",
        request1.preconf_transaction.first().unwrap().tx_hash()
    );
    assert!(
        txs.contains(&request1.tip_transaction),
        "User1's tip tx {:?} is in the constraints",
        request1.tip_transaction.tx_hash()
    );
    assert!(
        txs.contains(&request2.preconf_transaction.first().unwrap()),
        "User2's preconf tx {:?} should be in the constraints",
        request2.preconf_transaction.first().unwrap().tx_hash()
    );
    assert!(
        txs.contains(&request2.tip_transaction),
        "User2's tip tx {:?} should be in the constraints",
        request2.tip_transaction.tx_hash()
    );

    wait_until_deadline_of_slot(&config, target_slot + 1).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    // Verify only user1's transactions are in the block
    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            request1.tip_transaction.tx_hash().clone()
        )
        .await
        .is_ok(),
        "User1's tip tx is not in the block"
    );
    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            request1.preconf_transaction.first().unwrap().tx_hash().clone()
        )
        .await
        .is_ok(),
        "User1's preconf tx is not in the block"
    );
    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            request2.tip_transaction.tx_hash().clone()
        )
        .await
        .is_ok(),
        "User2's tip tx should be in the block"
    );
    assert!(
        verify_tx_in_block(
            &config.execution_url,
            block_number,
            request2.preconf_transaction.first().unwrap().tx_hash().clone()
        )
        .await
        .is_ok(),
        "User2's preconf tx should be in the block"
    );

    // Cleanup
    drop(taiyi_handle);
    Ok(())
}

#[tokio::test]
async fn test_type_a_and_type_b_requests() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(Url::from_str(&config.execution_url)?);
    let chain_id = provider.get_chain_id().await?;

    // Deposit 1ether to TaiyiCore
    taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config).await?;

    let balance = taiyi_balance(provider.clone(), signer.address(), &config).await?;
    assert_eq!(balance, U256::from(5 * ETH_TO_WEI));

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
        info!("slot: {}, tip_transaction: {:?}", target_slot, request.tip_transaction.tx_hash());
        for tx in &request.preconf_transaction {
            info!("slot: {}, preconf_transaction: {:?}", target_slot, tx.tx_hash());
        }
        let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
        let status = res.status();
        let body = res.bytes().await?;
        info!("submit Type A request response: {:?}", body);
        assert_eq!(status, 200);
        let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
        info!("preconf_response: {:?}", preconf_response);
        submitted_txs.push(request.tip_transaction.clone());
        submitted_txs.push(request.preconf_transaction.first().unwrap().clone());

        // Generate request and signature
        let (request, signature) = generate_reserve_blockspace_request(
            signer.clone(),
            target_slot,
            21_0000,
            0,
            fee,
            chain_id,
        )
        .await;

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

    wait_until_deadline_of_slot(&config, available_slot.get(requests_lim - 1).unwrap().slot + 1)
        .await?;
    assert!(verify_txs_inclusion(&config.execution_url, submitted_txs).await.is_ok());

    drop(taiyi_handle);
    Ok(())
}
