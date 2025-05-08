use std::{str::FromStr, sync::Arc};

use alloy_eips::{merge::SLOT_DURATION_SECS, BlockNumberOrTag};
use alloy_primitives::{hex, keccak256, Address, U256};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_rpc_types::Filter;
use alloy_signer::k256;
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
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

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

    let mut event_source = match EventSource::new(req) {
        Ok(source) => source,
        Err(err) => {
            error!("Failed to create EventSource: {:?}", err);
            return Ok(());
        }
    };

    while let Some(event) = event_source.next().await {
        match event {
            Ok(Event::Message(message)) => {
                let data = &message.data;

                let parsed_data = match serde_json::from_str::<
                    Vec<(PreconfRequest, PreconfResponseData)>,
                >(data)
                {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to parse preconf data: {}", e);
                        continue;
                    }
                };

                debug!("[Stream Ingestor]: Received {} preconfirmations", parsed_data.len());

                for (preconf_request, preconf_response_data) in parsed_data.iter() {
                    let target_slot = preconf_request.target_slot();
                    debug!(
                        "[Stream Ingestor]: Processing preconfirmation for slot {}",
                        target_slot
                    );

                    let commitment = match &preconf_response_data.commitment {
                        Some(c) => c,
                        None => {
                            error!("Missing commitment for slot {}", target_slot);
                            continue;
                        }
                    };

                    let preconf_request_data = PreconfRequestData {
                        preconf_type: match preconf_request {
                            PreconfRequest::TypeA(_) => 0,
                            PreconfRequest::TypeB(_) => 1,
                        },
                        preconf_request: match preconf_request {
                            PreconfRequest::TypeA(preconf_request) => {
                                match serde_json::to_string(preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to serialize TypeA request: {}", e);
                                        continue;
                                    }
                                }
                            }
                            PreconfRequest::TypeB(preconf_request) => {
                                match serde_json::to_string(preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to serialize TypeB request: {}", e);
                                        continue;
                                    }
                                }
                            }
                        },
                        preconf_request_signature: hex::encode(commitment.as_bytes()),
                    };

                    let challenge_id = keccak256(commitment.as_bytes()).to_string();

                    let write_tx = match preconf_db.begin_write() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to begin write transaction: {}", e);
                            continue;
                        }
                    };

                    {
                        let mut table = match write_tx.open_table(PRECONF_DATA_TABLE) {
                            Ok(t) => t,
                            Err(e) => {
                                error!("Failed to open PRECONF_DATA_TABLE: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = table.insert(&challenge_id, preconf_request_data) {
                            error!("Failed to insert preconf data: {}", e);
                            continue;
                        };
                    }

                    if let Err(e) = write_tx.commit() {
                        error!("Failed to commit write transaction: {}", e);
                        continue;
                    }

                    let read_tx = match preconf_db.begin_read() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to begin read transaction: {}", e);
                            continue;
                        }
                    };

                    let table = match read_tx.open_table(PRECONF_TABLE) {
                        Ok(t) => t,
                        Err(e) => {
                            error!("Failed to open PRECONF_TABLE: {}", e);
                            continue;
                        }
                    };

                    let preconfs = match table.get(&target_slot) {
                        Ok(Some(p)) => p.value(),
                        Ok(None) => Vec::new(),
                        Err(e) => {
                            error!("Failed to get preconfs: {}", e);
                            continue;
                        }
                    };

                    let mut preconfs = preconfs;
                    preconfs.push(challenge_id.clone());

                    let write_tx = match preconf_db.begin_write() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to begin write transaction: {}", e);
                            continue;
                        }
                    };

                    {
                        let mut table = match write_tx.open_table(PRECONF_TABLE) {
                            Ok(t) => t,
                            Err(e) => {
                                error!("Failed to open PRECONF_TABLE: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = table.insert(&target_slot, preconfs) {
                            error!("Failed to insert preconfs: {}", e);
                            continue;
                        };
                    }

                    if let Err(e) = write_tx.commit() {
                        error!("Failed to commit write transaction: {}", e);
                        continue;
                    }

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
    let provider = match ProviderBuilder::new().on_ws(ws).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create provider: {}", e);
            return Ok(());
        }
    };

    // Initialize signer
    let private_key =
        match hex::decode(opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key)) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to decode private key: {}", e);
                return Ok(());
            }
        };

    let signing_key = match k256::ecdsa::SigningKey::from_slice(&private_key) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to create signing key: {}", e);
            return Ok(());
        }
    };

    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(signing_key);

    // Underwriter address
    let signer_address = private_key_signer.address();

    // Filter for watching for challenge creations
    let filter = Filter::new()
        .address(opts.taiyi_challenger_address)
        .event("ChallengeOpened(bytes32 indexed, address indexed, address indexed)")
        .from_block(BlockNumberOrTag::Latest);

    let subscription = match provider.subscribe_logs(&filter).await {
        Ok(sub) => sub,
        Err(e) => {
            error!("Failed to subscribe to logs: {}", e);
            return Ok(());
        }
    };

    let mut stream = subscription.into_stream();

    while let Some(log) = stream.next().await {
        let challenge_opened_event =
            match log.log_decode::<TaiyiInteractiveChallenger::ChallengeOpened>() {
                Ok(event) => event,
                Err(e) => {
                    error!("Failed to decode challenge opened event: {}", e);
                    continue;
                }
            };

        let challenge_opened = challenge_opened_event.data();

        let challenge_id = challenge_opened.id;
        let challenger = challenge_opened.challenger;
        let commitment_signer = challenge_opened.commitmentSigner;
        let challenge_id_string = challenge_id.to_string();

        println!("Challenge opened: {challenge_id:?}");
        println!("Challenger: {challenger:?}");
        println!("Commitment signer: {commitment_signer:?}");

        if commitment_signer != signer_address {
            println!("Commitment signer is not underwriter, skipping");
            continue;
        }

        println!("Proving challenge...");

        let read_tx = match preconf_db.begin_read() {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to begin read transaction: {}", e);
                continue;
            }
        };

        let table = match read_tx.open_table(PRECONF_DATA_TABLE) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to open PRECONF_DATA_TABLE: {}", e);
                continue;
            }
        };

        let preconf_data = match table.get(&challenge_id_string) {
            Ok(Some(data)) => data,
            Ok(None) => {
                println!("Preconf data not found for challenge id {challenge_id_string}");
                continue;
            }
            Err(e) => {
                error!("Failed to get preconf data: {}", e);
                continue;
            }
        };

        let preconf_request_data = preconf_data.value();

        println!("Preconf request data: {preconf_request_data:?}");

        if preconf_request_data.preconf_type == 0 {
            // Generate proof for Type A
            let preconf_request = match serde_json::from_str::<PreconfRequestTypeA>(
                &preconf_request_data.preconf_request,
            ) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to parse TypeA request: {}", e);
                    continue;
                }
            };

            let mut user_transactions = Vec::new();
            for tx in preconf_request.preconf_tx.iter() {
                let user_transaction = match provider.get_transaction_by_hash(*tx.tx_hash()).await {
                    Ok(Some(tx)) => tx,
                    Ok(None) => {
                        error!("Transaction not found: {:?}", tx.tx_hash());
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to get transaction: {}", e);
                        continue;
                    }
                };
                user_transactions.push(user_transaction);
            }

            let tip_transaction = match provider
                .get_transaction_by_hash(*preconf_request.tip_transaction.tx_hash())
                .await
            {
                Ok(Some(tx)) => tx,
                Ok(None) => {
                    error!(
                        "Tip transaction not found: {:?}",
                        preconf_request.tip_transaction.tx_hash()
                    );
                    continue;
                }
                Err(e) => {
                    error!("Failed to get tip transaction: {}", e);
                    continue;
                }
            };

            let block_number = match tip_transaction.block_number {
                Some(num) => num,
                None => {
                    error!("Tip transaction has no block number");
                    continue;
                }
            };

            let inclusion_block =
                match provider.get_block_by_number(BlockNumberOrTag::Number(block_number)).await {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        error!("Block not found: {}", block_number);
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to get block: {}", e);
                        continue;
                    }
                };

            let previous_block = match provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number - 1))
                .await
            {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("Previous block not found: {}", block_number - 1);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get previous block: {}", e);
                    continue;
                }
            };

            let mut account_proofs = Vec::new();
            for tx in &user_transactions {
                let account_proof = match provider
                    .get_proof(tx.inner.signer(), vec![])
                    .block_id((block_number - 1).into())
                    .await
                {
                    Ok(proof) => proof,
                    Err(e) => {
                        error!("Failed to get account proof: {}", e);
                        continue;
                    }
                };

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
            let url = match Url::parse(&opts.execution_client_url) {
                Ok(url) => url,
                Err(e) => {
                    error!("Failed to parse execution client URL: {}", e);
                    continue;
                }
            };

            let mut txs_mpt_handler = match TxsMptHandler::new(url) {
                Ok(handler) => handler,
                Err(e) => {
                    error!("Failed to create TxsMptHandler: {}", e);
                    continue;
                }
            };

            if let Err(e) = txs_mpt_handler.build_tx_tree_from_block(block_number).await {
                error!("Failed to build tx tree: {}", e);
                continue;
            }

            let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

            // user txs
            for tx in &user_transactions {
                let tx_hash = tx.inner.tx_hash();
                let tx_index = match txs_mpt_handler.tx_hash_to_tx_index(*tx_hash) {
                    Ok(index) => index,
                    Err(e) => {
                        error!("Failed to get tx index: {}", e);
                        continue;
                    }
                };

                let proof = match txs_mpt_handler.get_proof(tx_index) {
                    Ok(proof) => proof,
                    Err(e) => {
                        error!("Failed to get tx proof: {}", e);
                        continue;
                    }
                };

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
                match serde_json::to_string(&inclusion_block.header) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize inclusion block header: {}", e);
                        continue;
                    }
                };
            stdin.write(&inclusion_block_header_serialized);

            // inclusion block hash
            stdin.write(&inclusion_block.header.hash_slow());

            // previous block header
            let previous_block_header_serialized =
                match serde_json::to_string(&previous_block.header) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize previous block header: {}", e);
                        continue;
                    }
                };
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
            let (_, report) = match client.execute(ELF_POI, &stdin).run() {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to execute program: {}", e);
                    continue;
                }
            };
            println!("Executed program with {} cycles", report.total_instruction_count());

            continue;
        }

        // Generate proof for Type B
        let preconf_request = match serde_json::from_str::<PreconfRequestTypeB>(
            &preconf_request_data.preconf_request,
        ) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse TypeB request: {}", e);
                continue;
            }
        };

        let user_transaction = match provider
            .get_transaction_by_hash(
                *preconf_request
                    .transaction
                    .ok_or_else(|| {
                        error!("No transaction in TypeB request");
                        eyre::eyre!("No transaction in TypeB request")
                    })?
                    .tx_hash(),
            )
            .await
        {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                error!("Transaction not found");
                continue;
            }
            Err(e) => {
                error!("Failed to get transaction: {}", e);
                continue;
            }
        };

        let block_number = match user_transaction.block_number {
            Some(num) => num,
            None => {
                error!("Transaction has no block number");
                continue;
            }
        };

        let inclusion_block =
            match provider.get_block_by_number(BlockNumberOrTag::Number(block_number)).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("Block not found: {}", block_number);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get block: {}", e);
                    continue;
                }
            };

        let previous_block =
            match provider.get_block_by_number(BlockNumberOrTag::Number(block_number - 1)).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("Previous block not found: {}", block_number - 1);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get previous block: {}", e);
                    continue;
                }
            };

        // account proof
        let account_proof = match provider
            .get_proof(user_transaction.inner.signer(), vec![])
            .block_id((block_number - 1).into())
            .await
        {
            Ok(proof) => proof,
            Err(e) => {
                error!("Failed to get account proof: {}", e);
                continue;
            }
        };

        let _account_merkle_proof = AccountMerkleProof {
            address: account_proof.address,
            nonce: account_proof.nonce,
            balance: account_proof.balance,
            storage_hash: account_proof.storage_hash,
            code_hash: account_proof.code_hash,
            account_proof: account_proof.account_proof,
            state_root: previous_block.header.state_root,
        };

        // tx proof
        let url = match Url::parse(&opts.execution_client_url) {
            Ok(url) => url,
            Err(e) => {
                error!("Failed to parse execution client URL: {}", e);
                continue;
            }
        };

        let mut txs_mpt_handler = match TxsMptHandler::new(url) {
            Ok(handler) => handler,
            Err(e) => {
                error!("Failed to create TxsMptHandler: {}", e);
                continue;
            }
        };

        if let Err(e) = txs_mpt_handler.build_tx_tree_from_block(block_number).await {
            error!("Failed to build tx tree: {}", e);
            continue;
        }

        let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

        // user tx
        let tx_hash = user_transaction.inner.tx_hash();
        let tx_index = match txs_mpt_handler.tx_hash_to_tx_index(*tx_hash) {
            Ok(index) => index,
            Err(e) => {
                error!("Failed to get tx index: {}", e);
                continue;
            }
        };

        let proof = match txs_mpt_handler.get_proof(tx_index) {
            Ok(proof) => proof,
            Err(e) => {
                error!("Failed to get tx proof: {}", e);
                continue;
            }
        };

        tx_merkle_proof.push(TxMerkleProof {
            key: alloy_rlp::encode(U256::from(tx_index)),
            proof,
            root: inclusion_block.header.transactions_root,
        });

        // SP1 part
        let mut stdin = SP1Stdin::new();

        // serde serialized preconf request type b
        stdin.write(&preconf_request_data.preconf_request);

        // hex-encoded preconfirmation signature
        stdin.write(&preconf_request_data.preconf_request_signature);

        // is type a
        stdin.write(&false);

        // inclusion block header
        let inclusion_block_header_serialized = match serde_json::to_string(&inclusion_block.header)
        {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize inclusion block header: {}", e);
                continue;
            }
        };
        stdin.write(&inclusion_block_header_serialized);

        // inclusion block hash
        stdin.write(&inclusion_block.header.hash_slow());

        // previous block header
        let previous_block_header_serialized = match serde_json::to_string(&previous_block.header) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize previous block header: {}", e);
                continue;
            }
        };
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
        let (_, report) = match client.execute(ELF_POI, &stdin).run() {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to execute program: {}", e);
                continue;
            }
        };
        println!("Executed program with {} cycles", report.total_instruction_count());
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

    let preconf_db = match Database::create("preconf.db") {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to create preconf database: {}", e);
            return Ok(());
        }
    };

    let preconf_db = Arc::new(preconf_db);

    // Create tables if they don't exist
    debug!("Creating tables...");
    let tx = match preconf_db.begin_write() {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin write transaction: {}", e);
            return Ok(());
        }
    };

    if let Err(e) = tx.open_table(PRECONF_TABLE) {
        error!("Failed to open PRECONF_TABLE: {}", e);
        return Ok(());
    }

    if let Err(e) = tx.commit() {
        error!("Failed to commit write transaction: {}", e);
        return Ok(());
    }

    debug!("Tables created successfully");

    // Read genesis timestamp from Beacon API (/eth/v1/beacon/genesis)
    let beacon_genesis_response = match reqwest::Client::new()
        .get(format!("{}/eth/v1/beacon/genesis", opts.beacon_url))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to send request to beacon API: {}", e);
            return Ok(());
        }
    };

    let beacon_genesis_response = match beacon_genesis_response.json::<serde_json::Value>().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to parse beacon API response: {}", e);
            return Ok(());
        }
    };

    let genesis_timestamp = match beacon_genesis_response["data"]["genesis_time"].as_str() {
        Some(time) => match u64::from_str(time) {
            Ok(timestamp) => timestamp,
            Err(e) => {
                error!("Failed to parse genesis timestamp: {}", e);
                return Ok(());
            }
        },
        None => {
            error!("Missing genesis_time in beacon API response");
            return Ok(());
        }
    };

    let mut handles = Vec::new();

    // Handles for ingesting underwriter streams
    let underwriter_stream_url = match Url::parse(&opts.underwriter_stream_url) {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to parse underwriter stream URL: {}", e);
            return Ok(());
        }
    };

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
