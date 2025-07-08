use alloy_consensus::{constants::ETH_TO_WEI, Transaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::address;
use alloy_primitives::{keccak256, Address, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_rpc_types_beacon::{
    relay::{Validator, ValidatorRegistration, ValidatorRegistrationMessage},
    BlsPublicKey, BlsSignature,
};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall, SolValue};
use axum::{
    extract::State,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use reqwest::Url;
use reqwest::{Client, Request};
use serde::de;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use taiyi_contracts::TaiyiEscrow;
use taiyi_primitives::constraints::{ConstraintsMessage, SignableBLS, SignedConstraints};
use taiyi_primitives::encode_util::{hex_decode, hex_to_u64};
use taiyi_primitives::{
    PreconfFee, PreconfRequestTypeA, PreconfResponseData, SubmitTransactionRequest,
};
use taiyi_underwriter::api::{
    Health, AVAILABLE_SLOTS, COMMITMENT_STREAM, HEALTH, PRECONF_FEE, RESERVE_BLOCKSPACE,
    RESERVE_SLOT_WITHOUT_CALLDATA, RESERVE_SLOT_WITH_CALLDATA,
};
use taiyi_underwriter::{
    api::run,
    event_stream::{DelegationMessage, SignedDelegation},
    slot_model::SlotModel,
};
use tokio::task::JoinHandle;
use tokio::{
    net::TcpListener,
    sync::{Notify, RwLock},
};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    constant::{UNDERWRITER_ADDRESS, UNDERWRITER_BLS_PK, UNDERWRITER_ECDSA_SK},
    contract_call::{revert_call, taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        generate_tx_with_nonce, generate_type_a_request, generate_type_a_request_with_nonce,
        get_available_slot, get_block_from_slot, get_constraints_from_relay, get_preconf_fee,
        health_check, new_account, send_reserve_blockspace_request, send_type_a_request,
        verify_tx_in_block, verify_txs_inclusion, ErrorResponse,
    },
};

// #[tokio::test]
// async fn test_preconf_fee() -> eyre::Result<()> {
//     // Start taiyi command in background
//     let (taiyi_handle, config) = setup_env().await?;

//     let available_slot = get_available_slot(&config.taiyi_url()).await?;
//     let target_slot = available_slot.first().unwrap().slot;
//     let preconf_fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;
//     info!("preconf_fee: {:?}", preconf_fee);

//     drop(taiyi_handle);
//     Ok(())
// }

pub async fn get_validators() -> impl IntoResponse {
    let slot_model = SlotModel::holesky();
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let slot = slot_model.get_slot(timestamp);
    let first_slot = slot_model.get_slot_number(slot);
    let validators: Vec<_> = (1..11)
        .map(|i| Validator {
            slot: first_slot + i,
            validator_index: 1,
            entry: ValidatorRegistration {
                message: ValidatorRegistrationMessage {
                    fee_recipient: address!("0xe68B08c865E292afE258e9694f811D08766BB044"),
                    gas_limit: 123456789,
                    timestamp: 123456789,
                    pubkey: BlsPublicKey::ZERO,
                },
                signature: BlsSignature::ZERO,
            },
        })
        .collect();
    Json(validators)
}

pub async fn get_delegations() -> impl IntoResponse {
    let delegations = vec![SignedDelegation {
        message: DelegationMessage {
            action: 1,
            validator_pubkey: BlsPublicKey::ZERO,
            delegatee_pubkey: BlsPublicKey::ZERO,
        },
        signature: BlsSignature::ZERO,
    }];
    Json(delegations)
}

pub async fn set_constraints(Json(request): Json<Vec<SignedConstraints>>) -> impl IntoResponse {
    println!("{request:?}");
    Json(json!({"status": "OK"}))
}

const EXECUTION_RPC_URL: &str = "https://rpc.holesky.luban.wtf";
const BEACON_RPC_URL: &str = "https://beacon.holesky.luban.wtf";
const TAIYI_ESCROW_ADDRESS: Address = address!("0xe68B08c865E292afE258e9694f811D08766BB044");

async fn start_test_preconf_api(
    taiyi_rpc_port: u16,
    relay_port: u16,
    relay_shutdown: Arc<Notify>,
) -> JoinHandle<()> {
    let relay_router = Router::new()
        .route("/relay/v1/builder/validators", get(get_validators))
        .route("/relay/v1/builder/delegations", get(get_delegations))
        .route("/constraints/v1/builder/constraints", post(set_constraints));

    let relay_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port);
    let taiyi_rpc_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let execution_rpc_url = EXECUTION_RPC_URL.to_string();
    let beacon_rpc_url = BEACON_RPC_URL.to_string();
    let taiyi_service_url = None;
    let bls_sk = "4942d3308d3fbfbdb977c0bf4c09cb6990aec9fd5ce24709eaf23d96dba71148".to_string();
    let ecdsa_sk = "5d2344259f42259f82d2c140aa66102ba89b57b4883ee441a8b312622bd42491".to_string();
    let relay_url = format!("http://{}", relay_addr.to_string());
    println!("relay_url {relay_url}");
    let fork_version = [5, 1, 112, 0];
    let genesis_timestamp = 1_695_902_400;

    let listener = TcpListener::bind(&relay_addr)
        .await
        .expect("Failed to create tcp listener for dummy relay");
    tokio::spawn(async move {
        let relay_shutdown = relay_shutdown.clone();
        let _ = tokio::select!(
            _ = axum::serve(listener, relay_router).with_graceful_shutdown(async move {
                relay_shutdown.notified().await
            }) => {},
            _ = run(
                taiyi_rpc_addr,
                taiyi_rpc_port,
                execution_rpc_url,
                beacon_rpc_url,
                taiyi_service_url,
                bls_sk,
                ecdsa_sk,
                relay_url,
                TAIYI_ESCROW_ADDRESS,
                fork_version,
                genesis_timestamp,
            ) => {}
        );
    })
}

#[tokio::test]
async fn test_health_check() -> eyre::Result<()> {
    let port = 5678;
    let relay_port = port + 1;
    let relay_shutdown = Arc::new(Notify::new());
    let api_handle = start_test_preconf_api(port, relay_port, relay_shutdown.clone()).await;
    let health_url = format!("http://localhost:{port}{HEALTH}");
    let health: Health = reqwest::Client::new().get(&health_url).send().await?.json().await?;
    //    let health: Health = tokio::time::timeout(Duration::from_millis(100), reqwest::Client::new().get(&health_url).send().await?.json()).await??;
    println!("health_check: {:?}", health);
    assert_eq!(health.status, "OK");

    relay_shutdown.notify_one();
    assert!(api_handle.await.is_ok());
    Ok(())
}

// #[tokio::test]
// async fn test_type_b_preconf_request() -> eyre::Result<()> {
//     let port = 5678;
//     let api_handle = start_test_preconf_api(port).await;

//     let execution_rpc_url = "https://rpc.holesky.luban.wtf".to_string();
//     let beacon_rpc_url = "https://beacon.holesky.luban.wtf".to_string();
//     let signer = new_account(&execution_rpc_url).await?;

//     let provider = ProviderBuilder::new()
//         .wallet(EthereumWallet::new(signer.clone()))
//         .connect_http(Url::from_str(&execution_rpc_url)?);

//     info!("type b preconf request");
//     let chain_id = provider.get_chain_id().await?;

//     // Deposit 1ether to TaiyiCore
//     taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config.taiyi_core).await?;

//     let balance = taiyi_balance(provider.clone(), signer.address(), &config.taiyi_core).await?;
//     assert_eq!(balance, U256::from(5 * ETH_TO_WEI));

//     // Pick a slot from the lookahead
//     let available_slot = get_available_slot(&config.taiyi_url()).await?;
//     info!("available_slot: {:?}", available_slot);
//     let target_slot = available_slot.first().unwrap().slot;

//     // Fetch preconf fee for the target slot
//     let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

//     // Generate request and signature
//     let (blockspace_request, signature) =
//         generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee, chain_id)
//             .await;

//     info!("Submitting request for target slot: {:?}", target_slot);

//     // Reserve blockspace
//     let res =
//         send_reserve_blockspace_request(blockspace_request.clone(), signature, &config.taiyi_url())
//             .await?;
//     let status = res.status();
//     let body = res.bytes().await?;
//     info!("reserve_blockspace response: {:?}", body);

//     let request_id = serde_json::from_slice::<Uuid>(&body)?;
//     assert_eq!(status, 200);

//     // Submit transaction
//     // Generate request and signature
//     let transaction = generate_tx(&execution_rpc_url, signer.clone()).await.unwrap();
//     let (request, signature) =
//         generate_submit_transaction_request(signer.clone(), transaction.clone(), request_id).await;

//     let res =
//         send_submit_transaction_request(request.clone(), signature, &config.taiyi_url()).await?;
//     let status = res.status();
//     let body = res.bytes().await?;
//     info!("submit transaction response: {:?}", body);
//     assert_eq!(status, 200);
//     let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
//     assert_eq!(preconf_response.request_id, request_id);

//     let commitment_string = preconf_response.commitment.unwrap();
//     let commitment = alloy_primitives::PrimitiveSignature::from_str(&commitment_string).unwrap();
//     let mut tx_bytes = Vec::new();
//     transaction.clone().encode_2718(&mut tx_bytes);
//     let raw_tx = format!("0x{}", hex::encode(&tx_bytes));
//     let data =
//         keccak256((blockspace_request.hash(chain_id), raw_tx.as_bytes()).abi_encode_packed());
//     let signer = commitment.recover_address_from_prehash(&data).unwrap();
//     assert!(signer == Address::from_str(UNDERWRITER_ADDRESS).unwrap());

//     wait_until_deadline_of_slot(&config, target_slot).await?;

//     let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
//     let mut txs = Vec::new();
//     for constraint in constraints.iter() {
//         let message = constraint.message.clone();
//         let decoded_txs = message.decoded_tx().unwrap();
//         txs.extend(decoded_txs);
//     }
//     assert!(txs.contains(&transaction));

//     let fee_recipient = Address::from_str("0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap();
//     let sponsor_eth_selector = TaiyiCore::sponsorEthBatchCall::SELECTOR;
//     let get_tip_selector = TaiyiCore::getTipCall::SELECTOR;
//     let mut sponsor_tx = None;
//     let mut get_tip_tx = None;
//     let mut payout_tx = None;
//     for tx in &txs {
//         if tx.kind().is_call() {
//             let selector = tx.input().get(0..4).unwrap_or_default();
//             if selector == sponsor_eth_selector {
//                 sponsor_tx = Some(tx.clone());
//             } else if selector == get_tip_selector {
//                 get_tip_tx = Some(tx.clone());
//             }
//         }

//         if payout_tx.is_none() && tx.to().unwrap() == fee_recipient {
//             payout_tx = Some(tx.clone());
//         }
//     }
//     assert!(sponsor_tx.is_some());
//     assert!(get_tip_tx.is_some());
//     assert!(payout_tx.is_some());

//     let signed_constraints = constraints.first().unwrap().clone();
//     let message = signed_constraints.message;

//     assert_eq!(
//         message.pubkey,
//         BlsPublicKey::try_from(hex::decode(UNDERWRITER_BLS_PK).unwrap().as_slice()).unwrap()
//     );
//     assert_eq!(message.slot, target_slot);

//     info!("Waiting for slot {} to be available", target_slot);

//     wait_until_deadline_of_slot(&config, target_slot + 1).await?;

//     let block_number = get_block_from_slot(&beacon_rpc_url, target_slot).await?;
//     info!("Block number: {}", block_number);

//     assert!(
//         verify_tx_in_block(&execution_rpc_url, block_number, transaction.tx_hash().clone())
//             .await
//             .is_ok(),
//         "tx is not in the block"
//     );

//     api_handle.abort();
//     assert!(api_handle.await.is_err());
//     Ok(())
// }

// #[tokio::test]
// async fn test_exhaust_is_called_for_requests_without_preconf_txs() -> eyre::Result<()> {
//     // Start taiyi command in background
//     let (taiyi_handle, config) = setup_env().await?;
//     let signer = new_account(EXECUTION_RPC_URL).await?;

//     let provider = ProviderBuilder::new()
//         .wallet(EthereumWallet::new(signer.clone()))
//         .connect_http(Url::from_str(EXECUTION_RPC_URL)?);
//     let chain_id = provider.get_chain_id().await?;

//     // Deposit 1ether to TaiyiCore
//     taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config.taiyi_core).await?;
//     let balance = taiyi_balance(provider.clone(), signer.address(), &config.taiyi_core).await?;
//     assert_eq!(balance, U256::from(5 * ETH_TO_WEI));
//     let available_slot = get_available_slot(&config.taiyi_url()).await?;
//     let target_slot = available_slot.first().unwrap().slot;
//     info!("Target slot: {:?}", target_slot);

//     let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

//     // Generate request and signature
//     let (request, signature) =
//         generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee, chain_id)
//             .await;

//     // Reserve blockspace
//     let res =
//         send_reserve_blockspace_request(request.clone(), signature, &config.taiyi_url()).await?;
//     let status = res.status();
//     assert_eq!(status, 200);

//     wait_until_deadline_of_slot(&config, target_slot).await?;

//     let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
//     let mut txs = Vec::new();
//     for constraint in constraints.iter() {
//         let message = constraint.message.clone();
//         let decoded_txs = message.decoded_tx().unwrap();
//         txs.extend(decoded_txs);
//     }

//     let exhaust_func_selector = TaiyiCore::exhaustCall::SELECTOR;

//     let mut exhaust_tx = None;
//     for tx in &txs {
//         if tx.kind().is_call() {
//             let selector = tx.input().get(0..4).unwrap();
//             if selector == exhaust_func_selector {
//                 exhaust_tx = Some(tx.clone());
//                 break;
//             }
//         }
//     }
//     assert!(exhaust_tx.is_some());

//     wait_until_deadline_of_slot(&config, target_slot + 1).await?;
//     let block_number = get_block_from_slot(BEACON_RPC_URL, target_slot).await?;
//     info!("Block number: {}", block_number);

//     assert!(
//         verify_tx_in_block(
//             EXECUTION_RPC_URL,
//             block_number,
//             exhaust_tx.unwrap().tx_hash().clone()
//         )
//         .await
//         .is_ok(),
//         "exhaust tx is not in the block"
//     );

//     let balance_after = taiyi_balance(provider, signer.address(), &config.taiyi_core).await?;
//     assert_eq!(balance_after, balance - request.deposit);

//     // Optionally, cleanup when done
//     drop(taiyi_handle);
//     Ok(())
// }

// // ============================= Type A preconf request =============================

#[tokio::test]
async fn test_type_a_preconf_request() -> eyre::Result<()> {
    let port = 5680;
    let relay_port = port + 1;
    let taiyi_url = format!("http://localhost:{port}");
    let relay_url = format!("http://localhost:{relay_port}");
    let relay_shutdown = Arc::new(Notify::new());
    let api_handle = start_test_preconf_api(port, relay_port, relay_shutdown.clone()).await;
    let signer = new_account(EXECUTION_RPC_URL).await?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(Url::from_str(EXECUTION_RPC_URL)?);
    let chain_id = provider.get_chain_id().await?;

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&taiyi_url).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&taiyi_url, target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_type_a_request(signer.clone(), target_slot, EXECUTION_RPC_URL, fee.clone())
            .await?;

    info!("Submitting request for target slot: {:?}", target_slot);
    info!("tip tx: {:?}", request.tip_transaction.tx_hash());
    for tx in &request.preconf_transaction {
        info!("preconf tx: {:?}", tx.tx_hash());
    }
    let res = send_type_a_request(request.clone(), signature, &taiyi_url).await?;
    let status = res.status();
    let body = res.bytes().await?;
    info!("submit Type A request response: {:?}", body);
    assert_eq!(status, 200);
    let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
    info!("preconf_response: {:?}", preconf_response);

    let commitment_string = preconf_response.commitment.unwrap();
    let commitment = alloy_primitives::Signature::from_str(&commitment_string).unwrap();
    let type_a = PreconfRequestTypeA {
        tip_transaction: request.tip_transaction.clone(),
        preconf_tx: request.preconf_transaction.clone(),
        target_slot: request.target_slot,
        sequence_number: preconf_response.sequence_num,
        signer: signer.address(),
        preconf_fee: PreconfFee::default(),
    };
    let data = type_a.digest(chain_id);
    let signer = commitment.recover_address_from_prehash(&data).unwrap();
    assert!(signer == Address::from_str(UNDERWRITER_ADDRESS).unwrap());

    // wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&relay_url, target_slot).await?;
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

    // wait_until_deadline_of_slot(&config, target_slot + 1).await?;
    let block_number = get_block_from_slot(BEACON_RPC_URL, target_slot).await?;
    info!("Block number: {}", block_number);

    assert!(
        verify_tx_in_block(
            EXECUTION_RPC_URL,
            block_number,
            request.tip_transaction.tx_hash().clone()
        )
        .await
        .is_ok(),
        "tip tx is not in the block"
    );
    assert!(
        verify_tx_in_block(
            EXECUTION_RPC_URL,
            block_number,
            request.preconf_transaction.first().unwrap().tx_hash().clone()
        )
        .await
        .is_ok(),
        "preconf tx is not in the block"
    );

    relay_shutdown.notify_one();
    assert!(api_handle.await.is_ok());
    Ok(())
}

// #[tokio::test]
// async fn test_send_multiple_type_a_preconf_for_the_same_slot() -> eyre::Result<()> {
//     // Start taiyi command in background
//     let (taiyi_handle, config) = setup_env().await?;

//     // Create two different users
//     let user1 = new_account(EXECUTION_RPC_URL).await?;
//     let user2 = new_account(EXECUTION_RPC_URL).await?;

//     // Pick a slot from the lookahead
//     let available_slot = get_available_slot(&config.taiyi_url()).await?;
//     let target_slot = available_slot.first().unwrap().slot;

//     // Fetch preconf fee for the target slot
//     let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

//     // Generate first request and signature from user1
//     let (request1, signature1) =
//         generate_type_a_request(user1.clone(), target_slot, EXECUTION_RPC_URL, fee.clone())
//             .await?;

//     info!("Submitting first request from user1 for target slot: {:?}", target_slot);
//     info!("user1 tip tx: {:?}", request1.tip_transaction.tx_hash());
//     for tx in &request1.preconf_transaction {
//         info!("user1 preconf tx: {:?}", tx.tx_hash());
//     }
//     let res1 = send_type_a_request(request1.clone(), signature1, &config.taiyi_url()).await?;
//     let status1 = res1.status();
//     let body1 = res1.bytes().await?;
//     info!("First Type A request response: {:?}", body1);
//     assert_eq!(status1, 200);
//     let preconf_response1: PreconfResponseData = serde_json::from_slice(&body1)?;
//     info!("First preconf_response: {:?}", preconf_response1);

//     // Generate second request and signature from user2 for the same slot
//     let (request2, signature2) =
//         generate_type_a_request(user2.clone(), target_slot, EXECUTION_RPC_URL, fee).await?;

//     info!("Submitting second request from user2 for target slot: {:?}", target_slot);
//     info!("user2 tip tx: {:?}", request2.tip_transaction.tx_hash());
//     for tx in &request2.preconf_transaction {
//         info!("user2 preconf tx: {:?}", tx.tx_hash());
//     }
//     let res2 = send_type_a_request(request2.clone(), signature2, &config.taiyi_url()).await?;
//     let status2 = res2.status();
//     let body2 = res2.bytes().await?;
//     info!("Second Type A request response: {:?}", body2);
//     assert_eq!(status2, 200);

//     // Verify only the first request's transactions are included in the constraints
//     wait_until_deadline_of_slot(&config, target_slot).await?;

//     let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
//     let mut txs = Vec::new();
//     for constraint in constraints.iter() {
//         let message = constraint.message.clone();
//         let decoded_txs = message.decoded_tx().unwrap();
//         txs.extend(decoded_txs);
//     }

//     // Check if constraints contains only user1's transactions
//     assert!(
//         txs.contains(&request1.preconf_transaction.first().unwrap()),
//         "User1's preconf tx {:?} is in the constraints",
//         request1.preconf_transaction.first().unwrap().tx_hash()
//     );
//     assert!(
//         txs.contains(&request1.tip_transaction),
//         "User1's tip tx {:?} is in the constraints",
//         request1.tip_transaction.tx_hash()
//     );
//     assert!(
//         txs.contains(&request2.preconf_transaction.first().unwrap()),
//         "User2's preconf tx {:?} should be in the constraints",
//         request2.preconf_transaction.first().unwrap().tx_hash()
//     );
//     assert!(
//         txs.contains(&request2.tip_transaction),
//         "User2's tip tx {:?} should be in the constraints",
//         request2.tip_transaction.tx_hash()
//     );

//     wait_until_deadline_of_slot(&config, target_slot + 1).await?;
//     let block_number = get_block_from_slot(BEACON_RPC_URL, target_slot).await?;
//     info!("Block number: {}", block_number);

//     // Verify only user1's transactions are in the block
//     assert!(
//         verify_tx_in_block(
//             EXECUTION_RPC_URL,
//             block_number,
//             request1.tip_transaction.tx_hash().clone()
//         )
//         .await
//         .is_ok(),
//         "User1's tip tx is not in the block"
//     );
//     assert!(
//         verify_tx_in_block(
//             EXECUTION_RPC_URL,
//             block_number,
//             request1.preconf_transaction.first().unwrap().tx_hash().clone()
//         )
//         .await
//         .is_ok(),
//         "User1's preconf tx is not in the block"
//     );
//     assert!(
//         verify_tx_in_block(
//             EXECUTION_RPC_URL,
//             block_number,
//             request2.tip_transaction.tx_hash().clone()
//         )
//         .await
//         .is_ok(),
//         "User2's tip tx should be in the block"
//     );
//     assert!(
//         verify_tx_in_block(
//             EXECUTION_RPC_URL,
//             block_number,
//             request2.preconf_transaction.first().unwrap().tx_hash().clone()
//         )
//         .await
//         .is_ok(),
//         "User2's preconf tx should be in the block"
//     );

//     // Cleanup
//     drop(taiyi_handle);
//     Ok(())
// }

// #[tokio::test]
// async fn test_type_a_and_type_b_requests() -> eyre::Result<()> {
//     // Start taiyi command in background
//     let (taiyi_handle, config) = setup_env().await?;
//     let signer = new_account(EXECUTION_RPC_URL).await?;

//     let provider = ProviderBuilder::new()
//         .wallet(EthereumWallet::new(signer.clone()))
//         .connect_http(Url::from_str(EXECUTION_RPC_URL)?);
//     let chain_id = provider.get_chain_id().await?;

//     // Deposit 1ether to TaiyiCore
//     taiyi_deposit(provider.clone(), 5 * ETH_TO_WEI, &config.taiyi_core).await?;

//     let balance = taiyi_balance(provider.clone(), signer.address(), &config.taiyi_core).await?;
//     assert_eq!(balance, U256::from(5 * ETH_TO_WEI));

//     let mut nonce = provider.get_transaction_count(signer.address()).await?;
//     let mut submitted_txs = Vec::new();

//     let available_slot = get_available_slot(&config.taiyi_url()).await?;
//     let requests_lim = available_slot.len().min(10);
//     for (idx, slot) in available_slot.iter().enumerate() {
//         if idx >= requests_lim {
//             break;
//         }
//         let target_slot = slot.slot;
//         let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

//         // Generate request and signature
//         let (request, signature) = generate_type_a_request_with_nonce(
//             signer.clone(),
//             target_slot,
//             EXECUTION_RPC_URL,
//             fee.clone(),
//             nonce,
//         )
//         .await?;
//         nonce += 2;
//         info!("slot: {}, tip_transaction: {:?}", target_slot, request.tip_transaction.tx_hash());
//         for tx in &request.preconf_transaction {
//             info!("slot: {}, preconf_transaction: {:?}", target_slot, tx.tx_hash());
//         }
//         let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
//         let status = res.status();
//         let body = res.bytes().await?;
//         info!("submit Type A request response: {:?}", body);
//         assert_eq!(status, 200);
//         let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
//         info!("preconf_response: {:?}", preconf_response);
//         submitted_txs.push(request.tip_transaction.clone());
//         submitted_txs.push(request.preconf_transaction.first().unwrap().clone());

//         // Generate request and signature
//         let (request, signature) = generate_reserve_blockspace_request(
//             signer.clone(),
//             target_slot,
//             21_0000,
//             0,
//             fee,
//             chain_id,
//         )
//         .await;

//         // Reserve blockspace
//         let res = send_reserve_blockspace_request(request.clone(), signature, &config.taiyi_url())
//             .await?;
//         let status = res.status();
//         let body = res.bytes().await?;
//         info!("reserve_blockspace response: {:?}", body);

//         let request_id = serde_json::from_slice::<Uuid>(&body)?;
//         assert_eq!(status, 200);

//         let transaction =
//             generate_tx_with_nonce(EXECUTION_RPC_URL, signer.clone(), nonce).await.unwrap();
//         let (request, signature) =
//             generate_submit_transaction_request(signer.clone(), transaction.clone(), request_id)
//                 .await;

//         let res = send_submit_transaction_request(request.clone(), signature, &config.taiyi_url())
//             .await?;
//         let status = res.status();
//         let body = res.bytes().await?;
//         info!("submit transaction response: {:?}", body);
//         assert_eq!(status, 200);
//         submitted_txs.push(transaction);

//         nonce += 1;
//     }

//     wait_until_deadline_of_slot(&config, available_slot.get(requests_lim - 1).unwrap().slot + 1)
//         .await?;
//     assert!(verify_txs_inclusion(EXECUTION_RPC_URL, submitted_txs).await.is_ok());

//     drop(taiyi_handle);
//     Ok(())
// }
