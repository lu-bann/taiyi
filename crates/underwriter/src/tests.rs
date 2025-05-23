#![allow(unused_variables)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use alloy_consensus::TxEnvelope;
use alloy_eips::Decodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_node_bindings::Anvil;
use alloy_primitives::{hex, Address, PrimitiveSignature, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use ethereum_consensus::deneb::Context;
use futures::StreamExt;
use parking_lot::Mutex;
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeResponse, PreconfRequest, PreconfRequestTypeB,
    PreconfResponseData, SubmitTransactionRequest,
};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    clients::{
        pricer::{ExecutionClientPricer, Pricer},
        relay_client::RelayClient,
        signer_client::SignerClient,
    },
    network_state::NetworkState,
    preconf_api::{
        api::{
            PreconfApiServer, COMMITMENT_STREAM_PATH, PRECONF_FEE_PATH, RESERVE_BLOCKSPACE_PATH,
            SUBMIT_TRANSACTION_PATH,
        },
        state::PreconfState,
    },
    preconf_pool::PreconfPoolBuilder,
};

sol! {
    #[sol(rpc, bytecode="6080604052348015600e575f80fd5b506101c38061001c5f395ff3fe608060405260043610610033575f3560e01c806327e235e31461003757806370a0823114610074578063d0e30db0146100a8575b5f80fd5b348015610042575f80fd5b5061006261005136600461013b565b5f6020819052908152604090205481565b60405190815260200160405180910390f35b34801561007f575f80fd5b5061006261008e36600461013b565b6001600160a01b03165f9081526020819052604090205490565b6100b06100b2565b005b5f34116101165760405162461bcd60e51b815260206004820152602860248201527f4465706f73697420616d6f756e74206d7573742062652067726561746572207460448201526768616e207a65726f60c01b606482015260840160405180910390fd5b335f9081526020819052604081208054349290610134908490610168565b9091555050565b5f6020828403121561014b575f80fd5b81356001600160a01b0381168114610161575f80fd5b9392505050565b8082018082111561018757634e487b7160e01b5f52601160045260245ffd5b9291505056fea26469706673582212205b3ebf660e7dcdb2d674f60a0229e4677c14be1e78d91ba988f92f12ade8038264736f6c63430008190033")]
    contract TaiyiEscrow {
        mapping(address => uint256) public balances;

        function balanceOf(address user) public view returns (uint256) {
            return balances[user];
        }

        function deposit() public payable {
            require(msg.value > 0, "Deposit amount must be greater than zero");
            balances[msg.sender] += msg.value;
        }
    }
}

#[tokio::test]
async fn test_preconf_api_server() -> eyre::Result<()> {
    let context = Context::for_mainnet();
    let network_state = NetworkState::new(context.clone());
    let slots = vec![20_000_000];
    for slot in 20_000_000..20_000_000 + 10 {
        network_state.add_slot(slot);
    }

    let relay_client = RelayClient::new(vec![]);

    let bls_sk = "4bd1960f5721d636400cb9dff7d17d5cfcc155f113280b8b9158596e2c0084ce".to_string();
    let ecdsa_sk = "0xa37e56991c7e88b7a4d80010a729fecce48fb2da505f3dccab7c2fa89bb69c4f".to_string();
    let ecdsa_pubkey =
        "03643b2c19f03891a7d103f50fab07ad0dbe7cb19477074d42488a28e345b07145".to_string();
    let signer_client = SignerClient::new(bls_sk, ecdsa_sk)?;

    let anvil = Anvil::new().block_time(12).chain_id(1).spawn();
    let rpc_url = anvil.endpoint();

    let sender = anvil.addresses().first().unwrap();
    let receiver = anvil.addresses().last().unwrap();
    let sender_pk = anvil.keys().first().unwrap();
    let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
    let wallet = EthereumWallet::from(signer.clone());
    let url = Url::from_str(&rpc_url)?;
    let provider = ProviderBuilder::new().wallet(wallet.clone()).on_http(url);
    let chain_id = provider.get_chain_id().await?;

    // Deploy escrow contract
    let escrow = TaiyiEscrow::deploy(&provider).await?;
    info!("Deployed contract at address: {}", escrow.address());

    // Deposit into the escrow contract
    let builder = escrow.deposit().value(U256::from(1_000_000_000_000_000_000_u128));
    let tx_hash = builder.send().await?.watch().await?;

    let builder = escrow.balanceOf(*sender);
    let balance = builder.call().await?._0;
    assert_eq!(balance, U256::from(1_000_000_000_000_000_000_u128));

    let pricer = Pricer::new(ExecutionClientPricer::new(provider.clone()));

    // spawn api server
    let state = PreconfState::new(
        network_state.clone(),
        relay_client,
        signer_client.clone(),
        rpc_url.parse().unwrap(),
        *escrow.address(),
        provider.clone(),
        pricer,
    );

    let preconfapiserver =
        PreconfApiServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5656));
    let server_endpoint = preconfapiserver.endpoint();
    let _ = preconfapiserver.run(state.clone()).await;

    // Estimate fee
    let request_endpoint = Url::parse(&server_endpoint).unwrap().join(PRECONF_FEE_PATH).unwrap();
    let response = reqwest::Client::new()
        .post(request_endpoint.clone())
        .json(network_state.available_slots().last().unwrap())
        .send()
        .await?;
    let status = response.status();
    assert_eq!(status, 200);
    let fee: PreconfFeeResponse = response.json().await?;

    // Reserve blockspace
    let request_endpoint =
        Url::parse(&server_endpoint).unwrap().join(RESERVE_BLOCKSPACE_PATH).unwrap();
    let (request, signature) = generate_reserve_blockspace_request(
        signer.clone(),
        *network_state.available_slots().last().unwrap(),
        fee,
        chain_id,
    )
    .await;
    let response = reqwest::Client::new()
        .post(request_endpoint.clone())
        .header("content-type", "application/json")
        .header("x-luban-signature", signature)
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    println!("{:?}", body);
    let request_id = serde_json::from_slice::<Uuid>(&body)?;
    assert_eq!(status, 200);

    // Submit transaction
    let request_endpoint =
        Url::parse(&server_endpoint).unwrap().join(SUBMIT_TRANSACTION_PATH).unwrap();
    let chain_id = provider.get_chain_id().await?;
    let sender = signer.address();
    let fees = provider.estimate_eip1559_fees().await?;
    let nonce = provider.get_transaction_count(sender).await?;
    let transaction = TransactionRequest::default()
        .with_from(sender)
        .with_value(U256::from(1000))
        .with_nonce(nonce)
        .with_gas_limit(21_000)
        .with_to(sender)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
        .with_chain_id(chain_id)
        .build(&wallet)
        .await?;

    let submit_transaction_request = SubmitTransactionRequest { request_id, transaction };
    let signature = hex::encode(
        signer.sign_hash(&submit_transaction_request.digest()).await.unwrap().as_bytes(),
    );

    let response = reqwest::Client::new()
        .post(request_endpoint.clone())
        .header("content-type", "application/json")
        .header("x-luban-signature", format!("0x{signature}"))
        .json(&submit_transaction_request)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    println!("{:?}", body);
    println!("Current block number: {:?}", provider.get_block_number().await?);
    let response: PreconfResponseData = serde_json::from_str(&body)?;
    assert_eq!(status, 200);

    Ok(())
}

async fn generate_reserve_blockspace_request(
    signer: PrivateKeySigner,
    target_slot: u64,
    preconf_fee: PreconfFeeResponse,
    chain_id: u64,
) -> (BlockspaceAllocation, String) {
    let fee = preconf_fee.gas_fee;
    let request = BlockspaceAllocation {
        target_slot,
        sender: signer.address(),
        recipient: Address::default(),
        deposit: U256::from(fee * 21_000 / 2),
        tip: U256::from(fee * 21_000 / 2),
        gas_limit: 21_000,
        blob_count: 0,
        preconf_fee,
    };
    let signature =
        hex::encode(signer.sign_hash(&request.hash(chain_id)).await.unwrap().as_bytes());
    (request, format!("0x{signature}"))
}

#[tokio::test]
async fn test_has_enough_balance() -> eyre::Result<()> {
    let anvil = Anvil::new().block_time(12).chain_id(0).spawn();
    let rpc_url = anvil.endpoint();

    let sender = anvil.addresses().first().unwrap();
    let sender_pk = anvil.keys().first().unwrap();
    let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
    let wallet = EthereumWallet::from(signer.clone());
    let url = Url::from_str(&rpc_url)?;
    let provider = ProviderBuilder::new().wallet(wallet.clone()).on_http(url);
    let chain_id = provider.get_chain_id().await?;

    // Deploy escrow contract
    let escrow = TaiyiEscrow::deploy(&provider).await?;
    println!("Deployed contract at address: {}", escrow.address());

    // Deposit into the escrow contract
    let builder = escrow.deposit().value(U256::from(500_000));
    let tx_hash = builder.send().await?.watch().await?;

    let builder = escrow.balanceOf(*sender);
    let balance = builder.call().await?._0;
    assert_eq!(balance, U256::from(500_000));

    let preconf_pool = PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), *escrow.address());

    let blockspace_request = BlockspaceAllocation {
        deposit: U256::from(100_000),
        tip: U256::from(100_000),
        ..Default::default()
    };
    let signature = signer.sign_hash(&blockspace_request.hash(chain_id)).await.unwrap();
    let preconf_request = PreconfRequestTypeB {
        allocation: blockspace_request,
        alloc_sig: signature,
        transaction: None,
        signer: signer.address(),
    };

    // Insert request into preconf pool
    let request_id = Uuid::new_v4();
    preconf_pool.insert_pending(request_id, preconf_request.clone());

    // Check if sender has enough balance for another request
    let res = preconf_pool.has_enough_balance(*sender, preconf_request.preconf_tip()).await;
    println!("{:?}", res);
    assert!(res.is_ok());
    // Insert request into preconf pool
    let request_id = Uuid::new_v4();
    preconf_pool.insert_pending(request_id, preconf_request.clone());

    // Sender must not have enough balance for another request
    assert!(preconf_pool.has_enough_balance(*sender, preconf_request.preconf_tip()).await.is_err());

    Ok(())
}

#[tokio::test]
async fn test_commitment_stream() -> eyre::Result<()> {
    let context = Context::for_mainnet();
    let network_state = NetworkState::new(context.clone());
    let slots = vec![20_000_000];
    for slot in 20_000_000..20_000_000 + 10 {
        network_state.add_slot(slot);
    }

    let relay_client = RelayClient::new(vec![]);

    let bls_sk = "4bd1960f5721d636400cb9dff7d17d5cfcc155f113280b8b9158596e2c0084ce".to_string();
    let ecdsa_sk = "0xa37e56991c7e88b7a4d80010a729fecce48fb2da505f3dccab7c2fa89bb69c4f".to_string();
    let ecdsa_pubkey =
        "03643b2c19f03891a7d103f50fab07ad0dbe7cb19477074d42488a28e345b07145".to_string();
    let signer_client = SignerClient::new(bls_sk, ecdsa_sk)?;

    let anvil = Anvil::new().block_time(12).chain_id(1).spawn();
    let rpc_url = anvil.endpoint();
    let url = Url::from_str(&rpc_url)?;
    let provider = ProviderBuilder::new().on_http(url);
    let chain_id = provider.get_chain_id().await?;

    let pricer = Pricer::new(ExecutionClientPricer::new(provider.clone()));

    // spawn api server
    let state = PreconfState::new(
        network_state.clone(),
        relay_client,
        signer_client.clone(),
        rpc_url.parse().unwrap(),
        Address::default(),
        provider.clone(),
        pricer,
    );

    let preconfapiserver =
        PreconfApiServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5656));
    let server_endpoint = preconfapiserver.endpoint();
    let _ = preconfapiserver.run(state.clone()).await;

    let request_endpoint =
        Url::parse(&server_endpoint).unwrap().join(COMMITMENT_STREAM_PATH).unwrap();
    let req = reqwest::Client::new().get(request_endpoint);
    let event_source = EventSource::new(req).unwrap_or_else(|err| {
        panic!("Failed to create EventSource: {:?}", err);
    });

    let received_commmitments = Arc::new(Mutex::new(Vec::new()));
    let received_commitments_clone = Arc::clone(&received_commmitments);

    tokio::spawn(async move {
        let mut event_source = event_source;
        while let Some(event) = event_source.next().await {
            match event {
                Ok(Event::Message(message)) => {
                    if message.event == "commitment_data" {
                        let data = &message.data;
                        println!("{}", data);
                        let parsed_data = serde_json::from_str::<
                            Vec<(PreconfRequest, PreconfResponseData)>,
                        >(data)
                        .unwrap()
                        .first()
                        .unwrap()
                        .clone();
                        let mut lock = received_commitments_clone.lock();
                        lock.push(parsed_data);
                    }
                }
                Ok(Event::Open) => {
                    info!("SSE connection opened");
                }
                Err(err) => {
                    error!("Error receiving SSE event: {:?}", err);
                }
            }
        }
    });

    // Delay to ensure the subscription is set up
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let raw_tx = alloy_primitives::hex::decode("02f86f0102843b9aca0085029e7822d68298f094d9e1459a7a482635700cbc20bbaf52d495ab9c9680841b55ba3ac080a0c199674fcb29f353693dd779c017823b954b3c69dffa3cd6b2a6ff7888798039a028ca912de909e7e6cdef9cdcaf24c54dd8c1032946dfa1d85c206b32a9064fe8").unwrap();
    let transaction = TxEnvelope::decode_2718(&mut raw_tx.as_slice()).unwrap();
    let preconf = PreconfRequestTypeB {
        allocation: BlockspaceAllocation { target_slot: 1, ..Default::default() },
        alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
        transaction: Some(transaction),
        signer: Address::default(),
    };
    let commitment = PrimitiveSignature::new(U256::ZERO, U256::ZERO, false);
    let test_data = (
        PreconfRequest::TypeB(preconf),
        PreconfResponseData {
            request_id: Uuid::default(),
            commitment: Some(format!("0x{}", hex::encode(commitment.as_bytes()))),
            sequence_num: None,
            current_slot: network_state.get_current_slot(),
        },
    );

    state.commitments_handle.send_commitment(test_data.clone());

    // Wait for the constraints to be received
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let locked_commitments = received_commmitments.lock();
    assert_eq!(locked_commitments.first().unwrap().clone(), test_data);

    Ok(())
}
