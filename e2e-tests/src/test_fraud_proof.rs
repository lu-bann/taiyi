use std::{fs, str::FromStr, time::Instant};

use alloy_consensus::{Account, Transaction};
use alloy_eips::{eip2718::Encodable2718, BlockNumberOrTag};
use alloy_primitives::{address, hex, Address, Bytes, PrimitiveSignature, B256, U256};
use alloy_provider::{ext::DebugApi, network::EthereumWallet, Provider, ProviderBuilder};
use alloy_rpc_types::{BlockTransactions, BlockTransactionsKind};
use alloy_signer::k256;
use alloy_sol_types::{sol, SolCall, SolValue};
use eth_trie_proofs::tx_trie::TxsMptHandler;
use ethereum_consensus::{crypto::PublicKey as BlsPublicKey, ssz::prelude::ssz_rs};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, network::FulfillmentStrategy, HashableKey, Prover, ProverClient, SP1Proof,
    SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use taiyi_preconfer::{context_ext::ContextExt, TaiyiCore};
use taiyi_primitives::PreconfResponseData;
use taiyi_zkvm_types::{
    types::{
        AccountMerkleProof, BlockspaceAllocation, PreconfRequestTypeA, PreconfRequestTypeB,
        PreconfTypeA, PreconfTypeB, TxMerkleProof,
    },
    utils::PublicValuesStruct,
};
use tracing::info;
use uuid::Uuid;

use crate::{
    constant::{PRECONFER_ADDRESS, PRECONFER_BLS_PK, PRECONFER_BLS_SK, PRECONFER_ECDSA_SK},
    contract_call::{taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        generate_type_a_request, generate_type_a_request_with_multiple_txs,
        generate_type_a_request_with_nonce, getTipCall, get_available_slot, get_block_from_slot,
        get_constraints_from_relay, get_preconf_fee, new_account, send_reserve_blockspace_request,
        send_submit_transaction_request, send_type_a_request, setup_env,
        wait_until_deadline_of_slot, PreconfTypeBJson,
    },
};

const ELF_POI: &[u8] = include_elf!("taiyi-poi");
const ELF_PONI: &[u8] = include_elf!("taiyi-poni");
const ELF_VERIFIER: &[u8] = include_elf!("taiyi-zkvm-verifier");

// TODO: type A not included test,
// TODO: type B not included test,

#[derive(Serialize, Deserialize)]
struct TestDataPreconfRequestTypeA {
    vk: String,
    proof: String,         // Hex encoded proof
    public_values: String, // Hex encoded public values
    preconf_request: PreconfRequestTypeA,
    abi_encoded_preconf_request: String,
    genesis_time: u64,
    taiyi_core: Address,
}

#[derive(Serialize, Deserialize)]
struct TestDataPreconfRequestTypeB {
    vk: String,
    proof: String,         // Hex encoded proof
    public_values: String, // Hex encoded public values
    preconf_request: PreconfRequestTypeB,
    abi_encoded_preconf_request: String,
    genesis_time: u64,
    taiyi_core: Address,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn verify_poi_preconf_type_a_included_proof() -> eyre::Result<()> {
    // Read proof from file
    let proof =
        SP1ProofWithPublicValues::load("test-data/poi-preconf-type-a-included-proof.bin").unwrap();

    // Read json data
    let test_data =
        fs::read_to_string("test-data/poi-preconf-type-a-included-test-data.json").unwrap();
    let test_data: TestDataPreconfRequestTypeA = serde_json::from_str(&test_data).unwrap();

    let (taiyi_handle, _) = setup_env().await?;

    let public_values = hex::decode(test_data.public_values).unwrap();
    let vk = test_data.vk;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof.bytes());
    stdin.write_vec(public_values);
    stdin.write(&vk);

    // Verify proof
    let client = ProverClient::builder().cpu().build();
    let (_, report) = client.execute(ELF_VERIFIER, &stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);

    taiyi_handle.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn verify_poi_preconf_type_a_multiple_txs_included_proof() -> eyre::Result<()> {
    // Read proof from file
    let proof = SP1ProofWithPublicValues::load(
        "test-data/poi-preconf-type-a-multiple-txs-included-proof.bin",
    )
    .unwrap();

    // Read json data
    let test_data =
        fs::read_to_string("test-data/poi-preconf-type-a-multiple-txs-included-test-data.json")
            .unwrap();
    let test_data: TestDataPreconfRequestTypeA = serde_json::from_str(&test_data).unwrap();

    let (taiyi_handle, _) = setup_env().await?;

    let public_values = hex::decode(test_data.public_values).unwrap();
    let vk = test_data.vk;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof.bytes());
    stdin.write_vec(public_values);
    stdin.write(&vk);

    // Verify proof
    let client = ProverClient::builder().cpu().build();
    let (_, report) = client.execute(ELF_VERIFIER, &stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);

    taiyi_handle.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn verify_poi_preconf_type_b_included_proof() -> eyre::Result<()> {
    // Read proof from file
    let proof =
        SP1ProofWithPublicValues::load("test-data/poi-preconf-type-b-included-proof.bin").unwrap();

    // Read json data
    let test_data =
        fs::read_to_string("test-data/poi-preconf-type-b-included-test-data.json").unwrap();
    let test_data: TestDataPreconfRequestTypeB = serde_json::from_str(&test_data).unwrap();

    println!("preconf b digest: {:?}", test_data.preconf_request.digest(3_151_908));

    let (taiyi_handle, _) = setup_env().await?;

    let public_values = hex::decode(test_data.public_values).unwrap();
    let vk = test_data.vk;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof.bytes());
    stdin.write_vec(public_values);
    stdin.write(&vk);

    // Verify proof
    let client = ProverClient::builder().cpu().build();
    let (_, report) = client.execute(ELF_VERIFIER, &stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);

    taiyi_handle.abort();
    Ok(())
}

#[cfg(not(feature = "ci"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn poi_preconf_type_a_included() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    // Initialize provider
    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&config.execution_url)
        .await?;

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
    let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();

    let body = res.bytes().await?;
    info!("submit Type A request response: {:?}", body);
    assert_eq!(status, 200);

    let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
    info!("preconf_response: {:?}", preconf_response);

    wait_until_deadline_of_slot(&config, target_slot).await?;

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

    let anchor_tx = txs.get(0).unwrap();
    let tip_tx = txs.get(1).unwrap();
    let user_tx = txs.get(2).unwrap();

    wait_until_deadline_of_slot(&config, target_slot + 2).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    let anchor_transaction = provider.get_transaction_by_hash(*anchor_tx.tx_hash()).await?.unwrap();
    let user_transaction = provider.get_transaction_by_hash(*user_tx.tx_hash()).await?.unwrap();
    let tip_transaction = provider.get_transaction_by_hash(*tip_tx.tx_hash()).await?.unwrap();

    let inclusion_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number), BlockTransactionsKind::Full)
        .await?
        .unwrap();

    let previous_block = provider
        .get_block_by_number(
            BlockNumberOrTag::Number(block_number - 1),
            BlockTransactionsKind::Full,
        )
        .await?
        .unwrap();

    // account proof
    let account_proof = provider
        .get_proof(user_transaction.from, vec![])
        .block_id((block_number - 1).into())
        .await?;

    let account_merkle_proof = AccountMerkleProof {
        address: account_proof.address,
        nonce: account_proof.nonce,
        balance: account_proof.balance,
        storage_hash: account_proof.storage_hash,
        code_hash: account_proof.code_hash,
        account_proof: account_proof.account_proof,
        state_root: previous_block.header.state_root,
    };

    // tx proof
    let url = Url::parse(&config.execution_url).unwrap();
    let mut txs_mpt_handler = TxsMptHandler::new(url).unwrap();
    txs_mpt_handler.build_tx_tree_from_block(block_number).await.unwrap();

    let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

    // anchor tx
    let tx_hash = anchor_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
    tx_merkle_proof.push(TxMerkleProof {
        key: alloy_rlp::encode(U256::from(tx_index)),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // user tx
    let tx_hash = user_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
    tx_merkle_proof.push(TxMerkleProof {
        key: alloy_rlp::encode(U256::from(tx_index)),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // SP1 part
    let mut stdin = SP1Stdin::new();

    // preconf type a
    let preconf_a = PreconfRequestTypeA {
        tip_transaction: tip_transaction.clone().into(),
        transactions: vec![user_transaction.clone().into()],
        target_slot,
        sequence_number: Some(1),
        signer: signer.address(),
    };

    let preconf_type_a = PreconfTypeA {
        preconf: preconf_a.clone(),
        anchor_tx: anchor_tx.clone().into(),
        tx_merkle_proof,
        account_merkle_proof: vec![account_merkle_proof],
    };

    // serde serialized preconf request type a
    let preconf_a_serialized = serde_json::to_string(&preconf_type_a).unwrap();
    stdin.write(&preconf_a_serialized);

    // hex-encoded preconfirmation signature
    let preconf_signature = hex::encode(preconf_response.commitment.unwrap().as_bytes());
    stdin.write(&preconf_signature);

    // is type a
    stdin.write(&true);

    // inclusion block header
    let inclusion_block_header_serialized = serde_json::to_string(&inclusion_block.header).unwrap();
    stdin.write(&inclusion_block_header_serialized);

    // inclusion block hash
    stdin.write(&inclusion_block.header.hash_slow());

    // previous block header
    let previous_block_header_serialized = serde_json::to_string(&previous_block.header).unwrap();
    stdin.write(&previous_block_header_serialized);

    // previous block hash
    stdin.write(&previous_block.header.hash_slow());

    // gateway address
    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
        k256::ecdsa::SigningKey::from_slice(&hex::decode(
            PRECONFER_ECDSA_SK.strip_prefix("0x").unwrap_or(&PRECONFER_ECDSA_SK),
        )?)?,
    );

    // gateway address
    let gateway_address = private_key_signer.address();
    stdin.write(&gateway_address);

    // genesis time
    let genesis_time = config.context.actual_genesis_time();
    stdin.write(&genesis_time);

    // taiyi core address
    let taiyi_core = config.taiyi_core;
    stdin.write(&taiyi_core);

    println!("Using the local/cpu SP1 prover.");
    let client = ProverClient::builder().cpu().build();

    println!("Executing program...");
    let (public_values, report) = client.execute(ELF_POI, &stdin).run().unwrap();
    println!("Executed program with {} cycles", report.total_instruction_count());

    // Decode public values
    let public_values_struct =
        PublicValuesStruct::abi_decode_sequence(public_values.as_slice(), true).unwrap();

    // Check block timestamp is correct (on-chain we will calculate the slot from the timestamp and compare it with the target slot in the challenge)
    assert_eq!(public_values_struct.proofBlockTimestamp, inclusion_block.header.timestamp);

    // Check block hash is correct
    assert_eq!(public_values_struct.proofBlockHash, inclusion_block.header.hash_slow());

    // Check gateway address is correct
    assert_eq!(public_values_struct.gatewayAddress, gateway_address);

    // Check signature is correct
    assert_eq!(
        hex::encode(public_values_struct.proofSignature),
        hex::encode(preconf_response.commitment.unwrap().as_bytes())
    );

    // Generate proof using prover network
    #[cfg(feature = "generate-proof")]
    {
        println!("Using the prover network.");
        let client = ProverClient::builder()
            .network()
            .rpc_url("https://rpc.production.succinct.xyz/")
            .private_key(&config.sp1_private_key)
            .build();

        // Generate the proof for the given program and input.
        let (pk, vk) = client.setup(ELF_POI);
        // Time proof generation
        let start = Instant::now();

        let proof = client
            .prove(&pk, &stdin)
            .plonk()
            .cycle_limit(1_000_000_000)
            .strategy(FulfillmentStrategy::Hosted)
            .skip_simulation(true)
            .run()
            .unwrap();

        let duration = start.elapsed();
        println!("Proof generation time: {:?}", duration);

        // Save proof in binary format
        proof.save("test-data/poi-preconf-type-a-included-proof.bin").expect("saving proof failed");

        let mut tip_tx = Vec::new();
        preconf_a.tip_transaction.encode_2718(&mut tip_tx);
        let tip_tx_raw = format!("0x{}", hex::encode(&tip_tx));

        let mut preconf_txs: Vec<String> = Vec::new();
        for tx in &preconf_a.transactions {
            let mut tx_bytes = Vec::new();
            tx.encode_2718(&mut tx_bytes);
            let hex_encoded_tx = format!("0x{}", hex::encode(&tx_bytes));
            preconf_txs.push(hex_encoded_tx);
        }

        let chain_id = provider.get_chain_id().await?;

        // Save proof and public values in json format
        let test_data = TestDataPreconfRequestTypeA {
            vk: vk.bytes32(),
            proof: hex::encode(proof.bytes()),
            public_values: hex::encode(public_values.as_slice()),
            preconf_request: preconf_a.clone(),
            abi_encoded_preconf_request: hex::encode(
                (
                    tip_tx_raw,
                    preconf_txs,
                    preconf_a.target_slot,
                    preconf_a.sequence_number.unwrap(),
                    preconf_a.signer,
                    chain_id,
                )
                    .abi_encode_sequence(),
            ),
            genesis_time,
            taiyi_core,
        };

        // Save test data in json format
        let test_data_json = serde_json::to_string(&test_data).unwrap();
        fs::write("test-data/poi-preconf-type-a-included-test-data.json", test_data_json).unwrap();
    }

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}

#[cfg(not(feature = "ci"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn poi_preconf_type_a_multiple_txs_included() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    // Initialize provider
    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&config.execution_url)
        .await?;

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) = generate_type_a_request_with_multiple_txs(
        signer.clone(),
        target_slot,
        &config.execution_url,
        fee.clone(),
        10,
    )
    .await?;

    info!("Submitting request for target slot: {:?}", target_slot);
    let res = send_type_a_request(request.clone(), signature, &config.taiyi_url()).await?;
    let status = res.status();

    let body = res.bytes().await?;
    info!("submit Type A request response: {:?}", body);

    assert_eq!(status, 200);

    let preconf_response: PreconfResponseData = serde_json::from_slice(&body)?;
    info!("preconf_response: {:?}", preconf_response);

    wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }

    // check if constraints contains our transactions
    for tx in request.preconf_transaction.iter() {
        assert!(txs.contains(tx));
    }
    assert!(txs.contains(&request.tip_transaction));

    let anchor_tx = txs.get(0).unwrap();
    let tip_tx = txs.get(1).unwrap();
    let user_txs = txs.iter().skip(2).take(txs.len() - 3).collect::<Vec<_>>();
    let _payout_tx = txs.last().unwrap();

    wait_until_deadline_of_slot(&config, target_slot + 2).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    let anchor_transaction = provider.get_transaction_by_hash(*anchor_tx.tx_hash()).await?.unwrap();
    let mut user_transactions = Vec::new();
    for tx in user_txs {
        let user_transaction = provider.get_transaction_by_hash(*tx.tx_hash()).await?.unwrap();
        user_transactions.push(user_transaction);
    }
    let tip_transaction = provider.get_transaction_by_hash(*tip_tx.tx_hash()).await?.unwrap();

    let inclusion_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number), BlockTransactionsKind::Full)
        .await?
        .unwrap();

    let previous_block = provider
        .get_block_by_number(
            BlockNumberOrTag::Number(block_number - 1),
            BlockTransactionsKind::Full,
        )
        .await?
        .unwrap();

    // account proofs
    let mut account_proofs = Vec::new();
    for tx in &user_transactions {
        let account_proof =
            provider.get_proof(tx.from, vec![]).block_id((block_number - 1).into()).await?;

        account_proofs.push(AccountMerkleProof {
            address: account_proof.address,
            nonce: account_proof.nonce,
            balance: account_proof.balance,
            storage_hash: account_proof.storage_hash,
            code_hash: account_proof.code_hash,
            account_proof: account_proof.account_proof,
            state_root: previous_block.header.state_root,
        });
    }

    // tx proof
    let url = Url::parse(&config.execution_url).unwrap();
    let mut txs_mpt_handler = TxsMptHandler::new(url).unwrap();
    txs_mpt_handler.build_tx_tree_from_block(block_number).await.unwrap();

    let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

    // anchor tx
    let tx_hash = anchor_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
    tx_merkle_proof.push(TxMerkleProof {
        key: alloy_rlp::encode(U256::from(tx_index)),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // user txs
    for tx in &user_transactions {
        let tx_hash = tx.inner.tx_hash();
        let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
        let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
        tx_merkle_proof.push(TxMerkleProof {
            key: alloy_rlp::encode(U256::from(tx_index)),
            proof,
            root: inclusion_block.header.transactions_root,
        });
    }

    // SP1 part
    let mut stdin = SP1Stdin::new();

    // preconf type a
    let preconf_a = PreconfRequestTypeA {
        tip_transaction: tip_transaction.clone().into(),
        transactions: user_transactions.iter().map(|tx| tx.clone().into()).collect(),
        target_slot,
        sequence_number: Some(1),
        signer: signer.address(),
    };

    let preconf_type_a = PreconfTypeA {
        preconf: preconf_a.clone(),
        anchor_tx: anchor_tx.clone().into(),
        tx_merkle_proof,
        account_merkle_proof: account_proofs,
    };

    // serde serialized preconf request type a
    let preconf_a_serialized = serde_json::to_string(&preconf_type_a).unwrap();
    stdin.write(&preconf_a_serialized);

    // hex-encoded preconfirmation signature
    let preconf_signature = hex::encode(preconf_response.commitment.unwrap().as_bytes());
    stdin.write(&preconf_signature);

    // is type a
    stdin.write(&true);

    // inclusion block header
    let inclusion_block_header_serialized = serde_json::to_string(&inclusion_block.header).unwrap();
    stdin.write(&inclusion_block_header_serialized);

    // inclusion block hash
    stdin.write(&inclusion_block.header.hash_slow());

    // previous block header
    let previous_block_header_serialized = serde_json::to_string(&previous_block.header).unwrap();
    stdin.write(&previous_block_header_serialized);

    // previous block hash
    stdin.write(&previous_block.header.hash_slow());

    // gateway address
    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
        k256::ecdsa::SigningKey::from_slice(&hex::decode(
            PRECONFER_ECDSA_SK.strip_prefix("0x").unwrap_or(&PRECONFER_ECDSA_SK),
        )?)?,
    );

    // gateway address
    let gateway_address = private_key_signer.address();
    stdin.write(&gateway_address);

    // genesis time
    let genesis_time = config.context.actual_genesis_time();
    stdin.write(&genesis_time);

    // taiyi core address
    let taiyi_core = config.taiyi_core;
    stdin.write(&taiyi_core);

    println!("Using the local/cpu SP1 prover.");
    let client = ProverClient::builder().cpu().build();

    println!("Executing program...");
    let (public_values, report) = client.execute(ELF_POI, &stdin).run().unwrap();
    println!("Executed program with {} cycles", report.total_instruction_count());

    // Decode public values
    let public_values_struct =
        PublicValuesStruct::abi_decode_sequence(public_values.as_slice(), true).unwrap();

    // Check block timestamp is correct (on-chain we will calculate the slot from the timestamp and compare it with the target slot in the challenge)
    assert_eq!(public_values_struct.proofBlockTimestamp, inclusion_block.header.timestamp);

    // Check block hash is correct
    assert_eq!(public_values_struct.proofBlockHash, inclusion_block.header.hash_slow());

    // Check gateway address is correct
    assert_eq!(public_values_struct.gatewayAddress, gateway_address);

    // Check signature is correct
    assert_eq!(
        hex::encode(public_values_struct.proofSignature),
        hex::encode(preconf_response.commitment.unwrap().as_bytes())
    );

    // Generate proof using prover network
    #[cfg(feature = "generate-proof")]
    {
        println!("Using the prover network.");
        let client = ProverClient::builder().network().private_key(&config.sp1_private_key).build();

        // Generate the proof for the given program and input.
        let (pk, vk) = client.setup(ELF_POI);

        // Time proof generation
        let start = Instant::now();

        let proof = client
            .prove(&pk, &stdin)
            .plonk()
            .cycle_limit(1_000_000_000)
            .strategy(FulfillmentStrategy::Hosted)
            .skip_simulation(true)
            .run()
            .unwrap();

        let duration = start.elapsed();
        println!("Proof generation time: {:?}", duration);

        // Save proof in binary format
        proof
            .save("test-data/poi-preconf-type-a-multiple-txs-included-proof.bin")
            .expect("saving proof failed");

        let mut tip_tx = Vec::new();
        preconf_a.tip_transaction.encode_2718(&mut tip_tx);
        let tip_tx_raw = format!("0x{}", hex::encode(&tip_tx));

        let mut preconf_txs: Vec<String> = Vec::new();
        for tx in &preconf_a.transactions {
            let mut tx_bytes = Vec::new();
            tx.encode_2718(&mut tx_bytes);
            let hex_encoded_tx = format!("0x{}", hex::encode(&tx_bytes));
            preconf_txs.push(hex_encoded_tx);
        }

        let chain_id = provider.get_chain_id().await?;

        let test_data = TestDataPreconfRequestTypeA {
            vk: vk.bytes32(),
            proof: hex::encode(proof.bytes()),
            public_values: hex::encode(public_values.as_slice()),
            preconf_request: preconf_a.clone(),
            abi_encoded_preconf_request: hex::encode(
                (
                    tip_tx_raw,
                    preconf_txs,
                    preconf_a.target_slot,
                    preconf_a.sequence_number.unwrap(),
                    preconf_a.signer,
                    chain_id,
                )
                    .abi_encode_sequence(),
            ),
            genesis_time,
            taiyi_core,
        };

        // Save test data in json format
        let test_data_serialized = serde_json::to_string(&test_data).unwrap();
        fs::write(
            "test-data/poi-preconf-type-a-multiple-txs-included-test-data.json",
            test_data_serialized,
        )
        .expect("saving test data failed");
    }

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}

#[cfg(not(feature = "ci"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn poi_preconf_type_b_included() -> eyre::Result<()> {
    // Start taiyi command in background
    let (_taiyi_handle, config) = setup_env().await?;
    let signer = new_account(&config).await?;

    // Initialize provider
    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&config.execution_url)
        .await?;
    let chain_id = provider.get_chain_id().await?;

    // Deposit 1ether to TaiyiCore
    taiyi_deposit(provider.clone(), 1_000_000_000_000_000, &config).await?;

    let balance = taiyi_balance(provider.clone(), signer.address(), &config).await?;
    assert_eq!(balance, U256::from(1_000_000_000_000_000u64));

    // Pick a slot from the lookahead
    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    info!("available_slot: {:?}", available_slot);
    let target_slot = available_slot.first().unwrap().slot;

    // Fetch preconf fee for the target slot
    let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(signer.clone(), target_slot, 21_0000, 0, fee, chain_id)
            .await;

    info!("Submitting request for target slot: {:?}", target_slot);

    // Reserve blockspace
    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    let status = res.status();

    let body = res.bytes().await?;
    info!("reserve_blockspace response: {:?}", body);
    assert_eq!(status, 200);

    let request_id = serde_json::from_slice::<Uuid>(&body)?;

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

    wait_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
    let mut txs = Vec::new();
    for constraint in constraints.iter() {
        let message = constraint.message.clone();
        let decoded_txs = message.decoded_tx().unwrap();
        txs.extend(decoded_txs);
    }
    assert_eq!(txs.len(), 4);
    assert!(txs.contains(&transaction));

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;

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

    let user_tx = transaction.clone();
    let tip_tx = get_tip_tx.unwrap();
    let sponsorship_tx = sponsor_tx.unwrap();

    assert_eq!(
        message.pubkey,
        BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
    );

    assert_eq!(message.slot, target_slot);

    info!("Waiting for slot {} to be available", target_slot);
    wait_until_deadline_of_slot(&config, target_slot + 2).await?;
    let block_number = get_block_from_slot(&config.beacon_url, target_slot).await?;
    info!("Block number: {}", block_number);

    let user_transaction = provider.get_transaction_by_hash(*user_tx.tx_hash()).await?.unwrap();
    let get_tip_transaction = provider.get_transaction_by_hash(*tip_tx.tx_hash()).await?.unwrap();
    let sponsorship_transaction =
        provider.get_transaction_by_hash(*sponsorship_tx.tx_hash()).await?.unwrap();

    let inclusion_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number), BlockTransactionsKind::Full)
        .await?
        .unwrap();

    let previous_block = provider
        .get_block_by_number(
            BlockNumberOrTag::Number(block_number - 1),
            BlockTransactionsKind::Full,
        )
        .await?
        .unwrap();

    let get_tip_call = getTipCall::abi_decode(get_tip_transaction.input(), true).unwrap();

    // account proof
    let account_proof = provider
        .get_proof(user_transaction.from, vec![])
        .block_id((block_number - 1).into())
        .await?;

    let account_merkle_proof = AccountMerkleProof {
        address: account_proof.address,
        nonce: account_proof.nonce,
        balance: account_proof.balance,
        storage_hash: account_proof.storage_hash,
        code_hash: account_proof.code_hash,
        account_proof: account_proof.account_proof,
        state_root: previous_block.header.state_root,
    };

    // tx proof
    let url = Url::parse(&config.execution_url).unwrap();
    let mut txs_mpt_handler = TxsMptHandler::new(url).unwrap();
    txs_mpt_handler.build_tx_tree_from_block(block_number).await.unwrap();

    let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

    // user tx
    let tx_hash = user_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();

    tx_merkle_proof.push(TxMerkleProof {
        key: alloy_rlp::encode(U256::from(tx_index)),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // sponsorship tx
    let tx_hash = sponsorship_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
    tx_merkle_proof.push(TxMerkleProof {
        key: alloy_rlp::encode(U256::from(tx_index)),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // SP1 part
    let mut stdin = SP1Stdin::new();

    // preconf type b
    let preconf_b = PreconfRequestTypeB {
        allocation: BlockspaceAllocation {
            sender: signer.address(),
            recipient: Address::from_str(PRECONFER_ADDRESS).unwrap(),
            gas_limit: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .gasLimit
                .try_into()
                .unwrap(),
            deposit: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .deposit
                .try_into()
                .unwrap(),
            tip: get_tip_call.preconfRequestBType.blockspaceAllocation.tip.try_into().unwrap(),
            target_slot: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .targetSlot
                .try_into()
                .unwrap(),
            blob_count: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .blobCount
                .try_into()
                .unwrap(),
        },
        alloc_sig: PrimitiveSignature::from_str(
            &get_tip_call.preconfRequestBType.blockspaceAllocationSignature.to_string(),
        )
        .unwrap(),
        transaction: Some(user_transaction.into()),
        signer: signer.address(),
    };

    let preconf_type_b = PreconfTypeB {
        preconf: preconf_b.clone(),
        sponsorship_tx: sponsorship_transaction.clone().into(),
        tx_merkle_proof,
        account_merkle_proof,
    };

    // serde serialized preconf request type b
    let preconf_type_b_serialized = serde_json::to_string(&preconf_type_b).unwrap();
    stdin.write(&preconf_type_b_serialized);

    // hex-encoded preconfirmation signature
    let preconf_signature = hex::encode(preconf_response.commitment.unwrap().as_bytes());
    stdin.write(&preconf_signature);

    // is type a
    stdin.write(&false);

    // inclusion block header
    let inclusion_block_header_serialized = serde_json::to_string(&inclusion_block.header).unwrap();
    stdin.write(&inclusion_block_header_serialized);

    // inclusion block hash
    stdin.write(&inclusion_block.header.hash_slow());

    // previous block header
    let previous_block_header_serialized = serde_json::to_string(&previous_block.header).unwrap();
    stdin.write(&previous_block_header_serialized);

    // previous block hash
    stdin.write(&previous_block.header.hash_slow());

    // gateway address
    let gateway_address = Address::from_str(PRECONFER_ADDRESS).unwrap();
    stdin.write(&gateway_address);

    // genesis time
    let genesis_time = config.context.actual_genesis_time();
    stdin.write(&genesis_time);

    // taiyi core address
    let taiyi_core = config.taiyi_core;
    stdin.write(&taiyi_core);

    println!("Using the local/cpu SP1 prover.");
    let client = ProverClient::builder().cpu().build();

    println!("Executing program...");
    let (public_values, report) = client.execute(ELF_POI, &stdin).run().unwrap();
    println!("Executed program with {} cycles", report.total_instruction_count());

    // Decode public values
    let public_values_struct =
        PublicValuesStruct::abi_decode_sequence(public_values.as_slice(), true).unwrap();

    // Check block timestamp is correct (on-chain we will calculate the slot from the timestamp and compare it with the target slot in the challenge)
    assert_eq!(public_values_struct.proofBlockTimestamp, inclusion_block.header.timestamp);
    // Check block hash is correct
    assert_eq!(public_values_struct.proofBlockHash, inclusion_block.header.hash_slow());
    // Check gateway address is correct
    assert_eq!(public_values_struct.gatewayAddress, gateway_address);
    // Check signature is correct
    assert_eq!(
        hex::encode(public_values_struct.proofSignature),
        hex::encode(preconf_response.commitment.unwrap().as_bytes())
    );

    // Generate proof using prover network
    #[cfg(feature = "generate-proof")]
    {
        println!("Using the prover network.");
        let client = ProverClient::builder().network().private_key(&config.sp1_private_key).build();

        // Generate the proof for the given program and input.
        let (pk, vk) = client.setup(ELF_POI);

        // Time proof generation
        let start = Instant::now();

        let proof = client
            .prove(&pk, &stdin)
            .plonk()
            .cycle_limit(1_000_000_000)
            .strategy(FulfillmentStrategy::Hosted)
            .skip_simulation(true)
            .run()
            .unwrap();

        let duration = start.elapsed();
        println!("Proof generation time: {:?}", duration);

        // Save proof in binary format
        proof.save("test-data/poi-preconf-type-b-included-proof.bin").expect("saving proof failed");

        let blockspace_allocation_encoded = (
            preconf_b.allocation.gas_limit,
            preconf_b.allocation.sender,
            preconf_b.allocation.recipient,
            preconf_b.allocation.deposit,
            preconf_b.allocation.tip,
            preconf_b.allocation.target_slot,
            preconf_b.allocation.blob_count as u64,
        )
            .abi_encode_sequence();

        let mut tx_bytes = Vec::new();
        preconf_b.clone().transaction.unwrap().encode_2718(&mut tx_bytes);
        let tx_encoded = format!("0x{}", hex::encode(&tx_bytes));

        let preconf_b_encoded = (
            hex::encode(blockspace_allocation_encoded),
            hex::encode(preconf_b.alloc_sig.as_bytes()),
            tx_encoded,
            preconf_b.signer,
            chain_id,
        )
            .abi_encode_sequence();

        let test_data = TestDataPreconfRequestTypeB {
            vk: vk.bytes32(),
            proof: hex::encode(proof.bytes()),
            public_values: hex::encode(public_values.as_slice()),
            preconf_request: preconf_b,
            abi_encoded_preconf_request: hex::encode(preconf_b_encoded),
            genesis_time,
            taiyi_core,
        };

        // Save test data in json format
        let test_data_serialized = serde_json::to_string(&test_data).unwrap();
        fs::write("test-data/poi-preconf-type-b-included-test-data.json", test_data_serialized)
            .expect("saving test data failed");
    }

    Ok(())
}
