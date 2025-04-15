use std::{str::FromStr, sync::Arc};

use alloy_eips::{eip2718::Encodable2718, merge::SLOT_DURATION_SECS, BlockNumberOrTag};
use alloy_primitives::{hex, keccak256, Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_rpc_types::Filter;
use alloy_signer::{
    k256::{self},
    Signer,
};
use alloy_sol_types::sol;
use clap::Parser;
use eth_trie_proofs::tx_trie::TxsMptHandler;
use futures_util::{future::join_all, StreamExt};
use redb::{Database, TableDefinition};
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use taiyi_primitives::{
    PreconfRequest, PreconfRequestTypeA, PreconfRequestTypeB, PreconfResponseData,
};
use taiyi_zkvm_types::types::{AccountMerkleProof, TxMerkleProof};
use tracing::{debug, error, level_filters::LevelFilter};

mod preconf_request_data;
use preconf_request_data::{Bincode, PreconfRequestData};
use sp1_sdk::{
    include_elf, network::FulfillmentStrategy, HashableKey, Prover, ProverClient, SP1Proof,
    SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};

const ELF_POI: &[u8] = include_elf!("taiyi-poi");

const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<String>>> = TableDefinition::new("preconf");

const PRECONF_DATA_TABLE: TableDefinition<String, Bincode<PreconfRequestData>> =
    TableDefinition::new("preconf_data");

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

#[derive(Parser, Clone)]
struct Opts {
    /// execution_client_url
    #[clap(long = "execution-client-url")]
    execution_client_url: String,
    /// execution_client_ws_url
    #[clap(long = "execution-client-ws-url")]
    execution_client_ws_url: String,
    /// beacon_url
    #[clap(long = "beacon-url")]
    beacon_url: String,
    /// underwriter stream url
    #[clap(long = "underwriter-stream-url")]
    underwriter_stream_url: String,
    /// Private key to sign transactions
    #[clap(long = "private-key")]
    private_key: String,
    /// Taiyi challenger contract address
    #[clap(long = "taiyi-challenger-address")]
    taiyi_challenger_address: Address,
    /// Private key to generate sp1 proofs
    #[clap(long = "sp1-private-key")]
    sp1_private_key: String,
}

sol! {
    #[sol(rpc)]
    contract TaiyiInteractiveChallenger {
        event ChallengeOpened(
            bytes32 indexed id, address indexed challenger, address indexed commitmentSigner
        );

        function prove(
            bytes32 id,
            bytes calldata proofValues,
            bytes calldata proofBytes
        )
            external;
    }
}

async fn handle_underwriter_stream(preconf_db: Arc<Database>, url: Url) -> eyre::Result<()> {
    let req = reqwest::Client::new().get(url);

    let mut event_source = EventSource::new(req).unwrap_or_else(|err| {
        panic!("Failed to create EventSource: {:?}", err);
    });

    while let Some(event) = event_source.next().await {
        match event {
            Ok(Event::Message(message)) => {
                let data = &message.data;

                let parsed_data =
                    serde_json::from_str::<Vec<(PreconfRequest, PreconfResponseData)>>(data)
                        .unwrap();

                debug!("[Stream Ingestor]: Received {} preconfirmations", parsed_data.len());

                for (preconf_request, preconf_response_data) in parsed_data.iter() {
                    let target_slot = preconf_request.target_slot();
                    debug!(
                        "[Stream Ingestor]: Processing preconfirmation for slot {}",
                        target_slot
                    );

                    let preconf_request_data = PreconfRequestData {
                        preconf_type: match preconf_request {
                            PreconfRequest::TypeA(_) => 0,
                            PreconfRequest::TypeB(_) => 1,
                        },
                        preconf_request: match preconf_request {
                            PreconfRequest::TypeA(preconf_request) => {
                                serde_json::to_string(preconf_request).unwrap()
                            }
                            PreconfRequest::TypeB(preconf_request) => {
                                serde_json::to_string(preconf_request).unwrap()
                            }
                        },
                        preconf_request_signature: hex::encode(
                            preconf_response_data.commitment.unwrap().as_bytes(),
                        ),
                    };

                    let challenge_id =
                        keccak256(preconf_response_data.commitment.unwrap().as_bytes()).to_string();

                    let write_tx = preconf_db.begin_write().unwrap();
                    {
                        let mut table = write_tx.open_table(PRECONF_DATA_TABLE).unwrap();
                        table.insert(&challenge_id, preconf_request_data).unwrap();
                    }
                    write_tx.commit().unwrap();

                    let read_tx = preconf_db.begin_read().unwrap();
                    let table = read_tx.open_table(PRECONF_TABLE).unwrap();
                    let preconfs = table.get(&target_slot);

                    if preconfs.is_err() {
                        // Storage error
                        error!(
                            "[Stream Ingestor]: Storage error for slot {}. Error: {:?}",
                            target_slot,
                            preconfs.err()
                        );
                        continue;
                    }

                    let preconfs = preconfs.unwrap();
                    let mut preconfs =
                        if preconfs.is_none() { Vec::new() } else { preconfs.unwrap().value() };

                    preconfs.push(challenge_id.clone());

                    let write_tx = preconf_db.begin_write().unwrap();
                    {
                        let mut table = write_tx.open_table(PRECONF_TABLE).unwrap();
                        table.insert(&target_slot, preconfs).unwrap();
                    }
                    write_tx.commit().unwrap();

                    debug!(
                        "[Stream Ingestor]: Stored preconfirmation for slot {} with challenge id {}",
                        target_slot, challenge_id
                    );
                }
            }
            Ok(Event::Open) => {
                debug!("[Stream Ingestor]: SSE connection opened");
            }
            Err(err) => {
                error!("[Stream Ingestor]: Error receiving SSE event: {:?}", err);
            }
        }
    }

    Ok(())
}

async fn respond_to_challenges(
    preconf_db: Arc<Database>,
    opts: Arc<Opts>,
    genesis_timestamp: u64,
) -> eyre::Result<()> {
    // Create a ws provider
    let ws = WsConnect::new(&opts.execution_client_ws_url);
    let provider = ProviderBuilder::new().on_ws(ws).await.unwrap();

    // Initialize signer
    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
        k256::ecdsa::SigningKey::from_slice(
            &hex::decode(opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key)).unwrap(),
        )
        .unwrap(),
    );

    // Underwriter address
    let signer_address = private_key_signer.address();

    // Filter for watching for challenge creations
    let filter = Filter::new()
        .address(opts.taiyi_challenger_address)
        .event("ChallengeOpened(bytes32 indexed, address indexed, address indexed)")
        .from_block(BlockNumberOrTag::Latest);

    let subscription = provider.subscribe_logs(&filter).await.unwrap();
    let mut stream = subscription.into_stream();

    while let Some(log) = stream.next().await {
        let challenge_opened_event =
            log.log_decode::<TaiyiInteractiveChallenger::ChallengeOpened>().unwrap();
        let challenge_opened = challenge_opened_event.data();

        let challenge_id = challenge_opened.id;
        let challenger = challenge_opened.challenger;
        let commitment_signer = challenge_opened.commitmentSigner;
        let challenge_id_string = challenge_id.to_string();

        println!("Challenge opened: {:?}", challenge_id);
        println!("Challenger: {:?}", challenger);
        println!("Commitment signer: {:?}", commitment_signer);

        if commitment_signer != signer_address {
            println!("Commitment signer is not underwriter, skipping");
            continue;
        }

        println!("Proving challenge...");

        let read_tx = preconf_db.begin_read().unwrap();
        let table = read_tx.open_table(PRECONF_DATA_TABLE).unwrap();
        let preconf_data = table.get(&challenge_id_string);

        if preconf_data.is_err() {
            println!("Failed to get preconf data for challenge id {}", challenge_id_string);
            continue;
        }

        let preconf_data = preconf_data.unwrap();

        if preconf_data.is_none() {
            println!("Preconf data not found for challenge id {}", challenge_id_string);
            continue;
        }

        let preconf_request_data = preconf_data.unwrap().value();

        println!("Preconf request data: {:?}", preconf_request_data);

        if preconf_request_data.preconf_type == 0 {
            // Generate proof for Type A
            let preconf_request =
                serde_json::from_str::<PreconfRequestTypeA>(&preconf_request_data.preconf_request)
                    .unwrap();

            let mut user_transactions = Vec::new();
            for tx in preconf_request.preconf_tx.iter() {
                let user_transaction =
                    provider.get_transaction_by_hash(*tx.tx_hash()).await?.unwrap();
                user_transactions.push(user_transaction);
            }

            let tip_transaction = provider
                .get_transaction_by_hash(*preconf_request.tip_transaction.tx_hash())
                .await?
                .unwrap();

            let block_number = tip_transaction.block_number.unwrap();

            let inclusion_block = provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number))
                .await?
                .unwrap();

            let previous_block = provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number - 1))
                .await?
                .unwrap();

            let mut account_proofs = Vec::new();
            for tx in &user_transactions {
                let account_proof = provider
                    .get_proof(tx.inner.signer(), vec![])
                    .block_id((block_number - 1).into())
                    .await?;

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
            let url = Url::parse(&opts.execution_client_url).unwrap();
            let mut txs_mpt_handler = TxsMptHandler::new(url).unwrap();
            txs_mpt_handler.build_tx_tree_from_block(block_number).await.unwrap();

            let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

            // TODO: How to get the anchor transaction?
            // anchor tx
            // let tx_hash = anchor_transaction.inner.tx_hash();
            // let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
            // let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
            // tx_merkle_proof.push(TxMerkleProof {
            //     key: alloy_rlp::encode(U256::from(tx_index)),
            //     proof,
            //     root: inclusion_block.header.transactions_root,
            // });
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

            // serde serialized preconf request type a
            stdin.write(&preconf_request_data.preconf_request);

            // hex-encoded preconfirmation signature
            stdin.write(&preconf_request_data.preconf_request_signature);

            // is type a
            stdin.write(&true);

            // inclusion block header
            let inclusion_block_header_serialized =
                serde_json::to_string(&inclusion_block.header).unwrap();
            stdin.write(&inclusion_block_header_serialized);

            // inclusion block hash
            stdin.write(&inclusion_block.header.hash_slow());

            // previous block header
            let previous_block_header_serialized =
                serde_json::to_string(&previous_block.header).unwrap();
            stdin.write(&previous_block_header_serialized);

            // previous block hash
            stdin.write(&previous_block.header.hash_slow());

            // underwriter address
            stdin.write(&signer_address);

            // genesis time
            stdin.write(&genesis_timestamp);

            // taiyi core address
            stdin.write(&opts.taiyi_challenger_address);

            println!("Using the local/cpu SP1 prover.");
            let client = ProverClient::builder().cpu().build();

            println!("Executing program...");
            let (_, report) = client.execute(ELF_POI, &stdin).run().unwrap();
            println!("Executed program with {} cycles", report.total_instruction_count());

            // TODO: Uncomment this when we know the program execution works
            // println!("Using the prover network.");
            // let client =
            //     ProverClient::builder().network().private_key(&opts.sp1_private_key).build();

            // // Generate the proof for the given program and input.
            // let (pk, vk) = client.setup(ELF_POI);

            // let proof = client
            //     .prove(&pk, &stdin)
            //     .plonk()
            //     .cycle_limit(100_000_000)
            //     .strategy(FulfillmentStrategy::Hosted)
            //     .skip_simulation(true)
            //     .run()
            //     .unwrap();

            // // Submit proof on chain
            // let taiyi_challenger =
            //     TaiyiInteractiveChallenger::new(opts.taiyi_challenger_address, provider.clone());

            // let proof_hex = hex::encode(proof.bytes());
            // let public_values_hex = hex::encode(proof.public_values.as_slice());

            // taiyi_challenger.prove(challenge_id, proof_hex.into(), public_values_hex.into());
            continue;
        }

        // Generate proof for Type B
        let preconf_request =
            serde_json::from_str::<PreconfRequestTypeB>(&preconf_request_data.preconf_request)
                .unwrap();

        let user_transaction = provider
            .get_transaction_by_hash(*preconf_request.transaction.unwrap().tx_hash())
            .await?
            .unwrap();

        let block_number = user_transaction.block_number.unwrap();

        let inclusion_block =
            provider.get_block_by_number(BlockNumberOrTag::Number(block_number)).await?.unwrap();

        let previous_block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number - 1))
            .await?
            .unwrap();

        // account proof
        let account_proof = provider
            .get_proof(user_transaction.inner.signer(), vec![])
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
        let url = Url::parse(&opts.execution_client_url).unwrap();
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

        // TODO: How to get sponsorship transaction?
        // sponsorship tx
        // let tx_hash = sponsorship_transaction.inner.tx_hash();
        // let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
        // let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
        // tx_merkle_proof.push(TxMerkleProof {
        //     key: alloy_rlp::encode(U256::from(tx_index)),
        //     proof,
        //     root: inclusion_block.header.transactions_root,
        // });

        // SP1 part
        let mut stdin = SP1Stdin::new();

        // serde serialized preconf request type b
        stdin.write(&preconf_request_data.preconf_request);

        // hex-encoded preconfirmation signature
        stdin.write(&preconf_request_data.preconf_request_signature);

        // is type a
        stdin.write(&false);

        // inclusion block header
        let inclusion_block_header_serialized =
            serde_json::to_string(&inclusion_block.header).unwrap();
        stdin.write(&inclusion_block_header_serialized);

        // inclusion block hash
        stdin.write(&inclusion_block.header.hash_slow());
        // previous block header
        let previous_block_header_serialized =
            serde_json::to_string(&previous_block.header).unwrap();
        stdin.write(&previous_block_header_serialized);

        // previous block hash
        stdin.write(&previous_block.header.hash_slow());

        // underwriter address
        stdin.write(&signer_address);

        // genesis time
        stdin.write(&genesis_timestamp);

        // taiyi core address
        stdin.write(&opts.taiyi_challenger_address);

        println!("Using the local/cpu SP1 prover.");
        let client = ProverClient::builder().cpu().build();

        println!("Executing program...");
        let (_, report) = client.execute(ELF_POI, &stdin).run().unwrap();
        println!("Executed program with {} cycles", report.total_instruction_count());

        // TODO: Uncomment this when we know the program execution works
        // println!("Using the prover network.");
        // let client =
        //     ProverClient::builder().network().private_key(&opts.sp1_private_key).build();

        // // Generate the proof for the given program and input.
        // let (pk, vk) = client.setup(ELF_POI);

        // let proof = client
        //     .prove(&pk, &stdin)
        //     .plonk()
        //     .cycle_limit(100_000_000)
        //     .strategy(FulfillmentStrategy::Hosted)
        //     .skip_simulation(true)
        //     .run()
        //     .unwrap();

        // let proof_hex = hex::encode(proof.bytes());
        // let public_values_hex = hex::encode(proof.public_values.as_slice());

        // taiyi_challenger.prove(challenge_id, proof_hex.into(), public_values_hex.into());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Read cli args
    let opts = Opts::parse();
    let opts = Arc::new(opts);

    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

    let preconf_db = Database::create("preconf.db").unwrap_or_else(|e| {
        eprintln!("Failed to create preconf database: {}", e);
        std::process::exit(1);
    });

    let preconf_db = Arc::new(preconf_db);

    // Create tables if they don't exist
    debug!("Creating tables...");
    let tx = preconf_db.begin_write().unwrap();
    tx.open_table(PRECONF_TABLE).unwrap();
    tx.commit().unwrap();
    debug!("Tables created successfully");

    // Read genesis timestamp from Beacon API (/eth/v1/beacon/genesis)
    let beacon_genesis_response = reqwest::Client::new()
        .get(format!("{}/eth/v1/beacon/genesis", opts.beacon_url))
        .send()
        .await
        .unwrap();

    let beacon_genesis_response =
        beacon_genesis_response.json::<serde_json::Value>().await.unwrap();
    let genesis_timestamp =
        u64::from_str(&beacon_genesis_response["data"]["genesis_time"].as_str().unwrap()).unwrap();

    let mut handles = Vec::new();

    // Handles for ingesting underwriter streams
    let underwriter_stream_url = Url::parse(&opts.underwriter_stream_url).unwrap();
    let underwriter_stream_handle =
        tokio::spawn(handle_underwriter_stream(preconf_db.clone(), underwriter_stream_url));
    handles.push(underwriter_stream_handle);

    // Handle for submitting challenges
    let prover_handle =
        tokio::spawn(respond_to_challenges(preconf_db.clone(), opts.clone(), genesis_timestamp));
    handles.push(prover_handle);

    let _ = join_all(handles).await;

    Ok(())
}
