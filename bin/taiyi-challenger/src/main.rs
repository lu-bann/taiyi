use std::{collections::HashSet, str::FromStr, sync::Arc};

use alloy_eips::{eip2718::Encodable2718, merge::SLOT_DURATION_SECS, BlockNumberOrTag};
use alloy_primitives::{hex, Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_signer::k256::{self};
use alloy_sol_types::sol;
use clap::Parser;
use futures_util::{future::join_all, StreamExt};
use redb::{Database, TableDefinition};
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use taiyi_primitives::{
    PreconfRequest, PreconfRequestTypeA, PreconfRequestTypeB, PreconfResponseData,
};
use tracing::{debug, error, level_filters::LevelFilter};

mod preconf_request_data;
use preconf_request_data::{Bincode, PreconfRequestData};

const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("preconf");
const CHALLENGE_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("challenge");

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

#[derive(Parser, Clone)]
struct Opts {
    /// execution_client_ws_url
    #[clap(long = "execution-client-ws-url")]
    execution_client_ws_url: String,
    /// beacon_url
    #[clap(long = "beacon-url")]
    beacon_url: String,
    /// finalization_window
    #[clap(long = "finalization-window")]
    finalization_window: u64,
    /// underwriter stream urls
    #[clap(long = "underwriter-stream-urls")]
    underwriter_stream_urls: Vec<String>,
    /// Private key to sign transactions
    #[clap(long = "private-key")]
    private_key: String,
    /// Taiyi challenger contract address
    #[clap(long = "taiyi-challenger-address")]
    taiyi_challenger_address: Address,
    /// Always open challenges
    #[clap(long = "always-open-challenges", default_value = "false")]
    always_open_challenges: bool,
}

sol! {
    #[sol(rpc)]
    contract TaiyiInteractiveChallenger {
        #[derive(Debug)]
        struct PreconfRequestAType {
            string[] txs;
            string tipTx;
            uint256 slot;
            uint256 sequenceNum;
            address signer;
        }

        #[derive(Debug)]
        struct BlockspaceAllocation {
            uint256 gasLimit;
            address sender;
            address recipient;
            uint256 deposit;
            uint256 tip;
            uint256 targetSlot;
            uint256 blobCount;
        }

        #[derive(Debug)]
        struct PreconfRequestBType {
            BlockspaceAllocation blockspaceAllocation;
            bytes blockspaceAllocationSignature;
            bytes underwriterSignedBlockspaceAllocation;
            bytes rawTx;
            bytes underwriterSignedRawTx;
        }


        #[derive(Debug)]
        function createChallengeAType(
            PreconfRequestAType calldata preconfRequestAType,
            bytes calldata signature
        )
            external
            payable;

        #[derive(Debug)]
        function createChallengeBType(
            PreconfRequestBType calldata preconfRequestBType,
            bytes calldata signature
        )
            external
            payable;

            #[derive(Debug)]
        function resolveExpiredChallenge(bytes32 id) external;
    }
}

async fn handle_underwriter_stream(preconf_db: Arc<Database>, url: Url) -> eyre::Result<()> {
    let req = reqwest::Client::new().get(url);

    let mut event_source = EventSource::new(req).unwrap_or_else(|err| {
        panic!("Failed to create EventSource: {err:?}");
    });

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
                        error!("[Stream Ingestor]: Failed to parse preconf data: {}", e);
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

                    let preconf_request_data = PreconfRequestData {
                        preconf_type: match preconf_request {
                            PreconfRequest::TypeA(_) => 0,
                            PreconfRequest::TypeB(_) => 1,
                        },
                        preconf_request: match preconf_request {
                            PreconfRequest::TypeA(preconf_request) => {
                                match serde_json::to_string(&preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("[Stream Ingestor]: Failed to serialize preconf request: {}", e);
                                        continue;
                                    }
                                }
                            }
                            PreconfRequest::TypeB(preconf_request) => {
                                match serde_json::to_string(&preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("[Stream Ingestor]: Failed to serialize preconf request: {}", e);
                                        continue;
                                    }
                                }
                            }
                        },
                        preconf_request_signature: match &preconf_response_data.commitment {
                            Some(commitment) => hex::encode(commitment.as_bytes()),
                            None => {
                                error!("[Stream Ingestor]: Missing commitment in preconf response");
                                continue;
                            }
                        },
                    };

                    let read_tx = match preconf_db.begin_read() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("[Stream Ingestor]: Failed to begin read transaction: {}", e);
                            continue;
                        }
                    };

                    let table = match read_tx.open_table(PRECONF_TABLE) {
                        Ok(table) => table,
                        Err(e) => {
                            error!("[Stream Ingestor]: Failed to open preconf table: {}", e);
                            continue;
                        }
                    };

                    let preconfs = table.get(&target_slot);
                    if preconfs.is_err() {
                        error!(
                            "[Stream Ingestor]: Storage error for slot {}. Error: {:?}",
                            target_slot,
                            preconfs.err()
                        );
                        continue;
                    }

                    let preconfs_result = match preconfs {
                        Ok(result) => result,
                        Err(e) => {
                            error!("[Stream Ingestor]: Failed to get preconfs: {}", e);
                            continue;
                        }
                    };

                    let mut preconf_values = if let Some(values) = preconfs_result {
                        values.value()
                    } else {
                        Vec::new()
                    };

                    preconf_values.push(preconf_request_data);

                    let write_result = (|| -> Result<(), redb::Error> {
                        let write_tx = preconf_db.begin_write()?;
                        {
                            let mut table = write_tx.open_table(PRECONF_TABLE)?;
                            table.insert(&target_slot, preconf_values)?;
                        }
                        write_tx.commit()?;
                        Ok(())
                    })();

                    if let Err(e) = write_result {
                        error!("[Stream Ingestor]: Failed to write preconf data: {}", e);
                        continue;
                    }

                    debug!("[Stream Ingestor]: Stored preconfirmation for slot {}", target_slot);
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

async fn handle_challenge_creation(
    preconf_db: Arc<Database>,
    challenge_db: Arc<Database>,
    opts: Arc<Opts>,
    genesis_timestamp: u64,
) -> eyre::Result<()> {
    // Create a ws provider
    let ws = WsConnect::new(&opts.execution_client_ws_url);
    let provider = match ProviderBuilder::new().on_ws(ws).await {
        Ok(provider) => provider,
        Err(e) => {
            error!("[Challenger Creator]: Failed to create provider: {}", e);
            return Err(eyre::eyre!("Failed to create provider: {}", e));
        }
    };

    // Subscribe to block headers.
    let subscription = match provider.subscribe_blocks().await {
        Ok(sub) => sub,
        Err(e) => {
            error!("[Challenger Creator]: Failed to subscribe to blocks: {}", e);
            return Err(eyre::eyre!("Failed to subscribe to blocks: {}", e));
        }
    };
    let mut stream = subscription.into_stream();

    while let Some(header) = stream.next().await {
        debug!("[Challenger Creator]: Processing block {:?}", header.number);
        let slot = get_slot_from_timestamp(header.timestamp, genesis_timestamp);
        debug!("[Challenger Creator]: Slot: {:?}", slot);

        // Check if preconfirmations exists for the slot
        let read_tx = match preconf_db.begin_read() {
            Ok(tx) => tx,
            Err(e) => {
                error!("[Challenger Creator]: Failed to begin read transaction: {}", e);
                continue;
            }
        };

        let table = match read_tx.open_table(PRECONF_TABLE) {
            Ok(table) => table,
            Err(e) => {
                error!("[Challenger Creator]: Failed to open preconf table: {}", e);
                continue;
            }
        };

        let preconfs = table.get(&slot);

        if preconfs.is_err() {
            error!(
                "[Challenger Creator]: Storage error for slot {}. Error: {:?}",
                slot,
                preconfs.err()
            );
            continue;
        }

        let preconfs_result = match preconfs {
            Ok(result) => result,
            Err(e) => {
                error!("[Challenger Creator]: Failed to get preconfs: {}", e);
                continue;
            }
        };

        if preconfs_result.is_none() {
            // No preconfirmation found for the slot
            debug!("[Challenger Creator]: No preconfirmations found for slot {}", slot);
            continue;
        }

        let preconfs = match preconfs_result {
            Some(values) => values.value(),
            None => {
                debug!("[Challenger Creator]: No preconfirmations found for slot {}", slot);
                continue;
            }
        };

        debug!("[Challenger Creator]: Found {} preconfirmations for slot {}", preconfs.len(), slot);

        let block = provider.get_block_by_number(BlockNumberOrTag::Number(header.number)).await;

        if block.is_err() {
            // RPC error
            error!(
                "[Challenger Creator]: RPC error for block {}. Error: {:?}",
                header.number,
                block.err()
            );
            continue;
        }

        let block = match block {
            Ok(Some(b)) => b,
            Ok(None) => {
                error!("[Challenger Creator]: Block {} not found", header.number);
                continue;
            }
            Err(e) => {
                error!("[Challenger Creator]: Failed to get block {}: {}", header.number, e);
                continue;
            }
        };

        let tx_hashes = block.transactions.hashes().collect::<HashSet<_>>();

        // Calculate the challenge submission slot. We need to wait for the block to be finalized
        // before we can open a challenge.
        let challenge_submission_slot = slot + opts.finalization_window;

        // For each preconfirmation, check if the required txs are included in the block
        for preconf in preconfs {
            let preconf_type = preconf.preconf_type;

            if preconf_type == 0 {
                // Type A
                let preconf_request =
                    match serde_json::from_str::<PreconfRequestTypeA>(&preconf.preconf_request) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(
                                "[Challenger Creator]: Failed to parse PreconfRequestTypeA: {}",
                                e
                            );
                            continue;
                        }
                    };

                let mut open_challenge = false;

                // Check if all user txs are included in the block
                if !preconf_request.preconf_tx.iter().all(|tx| tx_hashes.contains(tx.tx_hash())) {
                    open_challenge = true;
                }

                // Check if tip transaction is included in the block
                if !tx_hashes.contains(preconf_request.tip_transaction.tx_hash()) {
                    open_challenge = true;
                }

                if open_challenge || opts.always_open_challenges {
                    let read_tx = match challenge_db.begin_read() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("[Challenger Creator]: Failed to begin read transaction: {}", e);
                            continue;
                        }
                    };

                    let table = match read_tx.open_table(CHALLENGE_TABLE) {
                        Ok(table) => table,
                        Err(e) => {
                            error!("[Challenger Creator]: Failed to open challenge table: {}", e);
                            continue;
                        }
                    };

                    let challenges = table.get(&challenge_submission_slot);

                    if challenges.is_err() {
                        error!(
                            "[Challenger Creator]: Storage error for slot {}. Error: {:?}",
                            challenge_submission_slot,
                            challenges.err()
                        );
                        continue;
                    }

                    let challenges_result = match challenges {
                        Ok(result) => result,
                        Err(e) => {
                            error!("[Challenger Creator]: Failed to get challenges: {}", e);
                            continue;
                        }
                    };

                    let mut challenges_data = if let Some(values) = challenges_result {
                        values.value()
                    } else {
                        Vec::new()
                    };

                    challenges_data.push(preconf);

                    let write_result = (|| -> Result<(), redb::Error> {
                        let write_tx = challenge_db.begin_write()?;
                        {
                            let mut table = write_tx.open_table(CHALLENGE_TABLE)?;
                            table.insert(&challenge_submission_slot, challenges_data)?;
                        }
                        write_tx.commit()?;
                        Ok(())
                    })();

                    if let Err(e) = write_result {
                        error!("[Challenger Creator]: Failed to write challenge data: {}", e);
                        continue;
                    }

                    debug!(
                        "[Challenger Creator]: Stored challenge for slot {}",
                        challenge_submission_slot
                    );
                }
            } else {
                // Type B
                let preconf_request =
                    match serde_json::from_str::<PreconfRequestTypeB>(&preconf.preconf_request) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(
                                "[Challenger Creator]: Failed to parse PreconfRequestTypeB: {}",
                                e
                            );
                            continue;
                        }
                    };

                let transaction = match &preconf_request.transaction {
                    Some(tx) => tx,
                    None => {
                        error!("[Challenger Creator]: Missing transaction in PreconfRequestTypeB");
                        continue;
                    }
                };

                // Check if all user txs are included in the block
                if !tx_hashes.contains(transaction.tx_hash()) || opts.always_open_challenges {
                    let read_tx = match challenge_db.begin_read() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("[Challenger Creator]: Failed to begin read transaction: {}", e);
                            continue;
                        }
                    };

                    let table = match read_tx.open_table(CHALLENGE_TABLE) {
                        Ok(table) => table,
                        Err(e) => {
                            error!("[Challenger Creator]: Failed to open challenge table: {}", e);
                            continue;
                        }
                    };

                    let challenges = table.get(&slot);

                    if challenges.is_err() {
                        error!(
                            "[Challenger Creator]: Storage error for slot {}. Error: {:?}",
                            slot,
                            challenges.err()
                        );
                        continue;
                    }

                    let challenges_result = match challenges {
                        Ok(result) => result,
                        Err(e) => {
                            error!("[Challenger Creator]: Failed to get challenges: {}", e);
                            continue;
                        }
                    };

                    let mut challenges_data = if let Some(values) = challenges_result {
                        values.value()
                    } else {
                        Vec::new()
                    };

                    challenges_data.push(preconf);

                    let write_result = (|| -> Result<(), redb::Error> {
                        let write_tx = challenge_db.begin_write()?;
                        {
                            let mut table = write_tx.open_table(CHALLENGE_TABLE)?;
                            table.insert(&slot, challenges_data)?;
                        }
                        write_tx.commit()?;
                        Ok(())
                    })();

                    if let Err(e) = write_result {
                        error!("[Challenger Creator]: Failed to write challenge data: {}", e);
                        continue;
                    }

                    debug!("[Challenger Creator]: Stored challenge for slot {}", slot);
                }
            }
        }

        debug!("[Challenger Creator]: Processed block {:?}", header.number);
    }

    Ok(())
}

async fn handle_challenge_submission(
    challenge_db: Arc<Database>,
    opts: Arc<Opts>,
    genesis_timestamp: u64,
) -> eyre::Result<()> {
    // Initialize signer
    let private_key_bytes =
        match hex::decode(opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key)) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to decode private key: {}", e);
                return Err(eyre::eyre!("Failed to decode private key: {}", e));
            }
        };

    let signing_key = match k256::ecdsa::SigningKey::from_slice(&private_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            error!("[Challenger Submitter]: Failed to create signing key: {}", e);
            return Err(eyre::eyre!("Failed to create signing key: {}", e));
        }
    };

    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(signing_key);
    let signer_address = private_key_signer.address();

    debug!("[Challenger Submitter]: Signer address: {}", signer_address);

    let ws = WsConnect::new(&opts.execution_client_ws_url);
    let provider = match ProviderBuilder::new().wallet(private_key_signer).on_ws(ws).await {
        Ok(p) => p,
        Err(e) => {
            error!("[Challenger Submitter]: Failed to create provider with wallet: {}", e);
            return Err(eyre::eyre!("Failed to create provider with wallet: {}", e));
        }
    };

    // Check balance to verify signer is working correctly
    match provider.get_balance(signer_address).await {
        Ok(balance) => {
            debug!("[Challenger Submitter]: Signer ETH balance: {}", balance);
        }
        Err(e) => {
            error!("[Challenger Submitter]: Failed to get signer balance: {}", e);
            // Continue anyway, this is not critical
        }
    };

    let taiyi_challenger =
        TaiyiInteractiveChallenger::new(opts.taiyi_challenger_address, provider.clone());

    let subscription = match provider.subscribe_blocks().await {
        Ok(sub) => sub,
        Err(e) => {
            error!("[Challenger Submitter]: Failed to subscribe to blocks: {}", e);
            return Err(eyre::eyre!("Failed to subscribe to blocks: {}", e));
        }
    };

    let mut stream = subscription.into_stream();

    while let Some(header) = stream.next().await {
        debug!("[Challenger Submitter]: Processing block {:?}", header.number);
        let slot = get_slot_from_timestamp(header.timestamp, genesis_timestamp);
        debug!("[Challenger Submitter]: Slot: {:?}", slot);

        // Check if challenges exists for the slot
        let read_tx = match challenge_db.begin_read() {
            Ok(tx) => tx,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to begin read transaction: {}", e);
                continue;
            }
        };

        let table = match read_tx.open_table(CHALLENGE_TABLE) {
            Ok(table) => table,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to open challenge table: {}", e);
                continue;
            }
        };

        let challenges = table.get(&slot);

        if challenges.is_err() {
            error!(
                "[Challenger Submitter]: Storage error for slot {}. Error: {:?}",
                slot,
                challenges.err()
            );
            continue;
        }

        let challenges_result = match challenges {
            Ok(result) => result,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to get challenges: {}", e);
                continue;
            }
        };

        if challenges_result.is_none() {
            // No challenges found for the slot
            debug!("[Challenger Submitter]: No challenges found for slot {}", slot);
            continue;
        }

        let challenges_data = match challenges_result {
            Some(values) => values.value(),
            None => {
                debug!("[Challenger Submitter]: No challenges found for slot {}", slot);
                continue;
            }
        };

        debug!(
            "[Challenger Submitter]: Found {} challenges for slot {}",
            challenges_data.len(),
            slot
        );

        // For each challenge, check if the challenge is expired
        for challenge in challenges_data {
            if challenge.preconf_type == 0 {
                // Type A
                let preconf_request =
                    match serde_json::from_str::<PreconfRequestTypeA>(&challenge.preconf_request) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(
                                "[Challenger Submitter]: Failed to parse PreconfRequestTypeA: {}",
                                e
                            );
                            continue;
                        }
                    };

                let mut txs: Vec<String> = Vec::new();

                for tx in preconf_request.preconf_tx {
                    let mut tx_bytes = Vec::new();
                    tx.encode_2718(&mut tx_bytes);
                    let hex_encoded_tx = format!("0x{}", hex::encode(&tx_bytes));
                    txs.push(hex_encoded_tx);
                }

                let mut tip_tx = Vec::new();
                preconf_request.tip_transaction.encode_2718(&mut tip_tx);
                let tip_tx_raw = format!("0x{}", hex::encode(&tip_tx));

                let sequence_number = match preconf_request.sequence_number {
                    Some(num) => num,
                    None => {
                        error!("[Challenger Submitter]: Missing sequence number in PreconfRequestTypeA");
                        continue;
                    }
                };

                let preconf_request_a_type = TaiyiInteractiveChallenger::PreconfRequestAType {
                    txs,
                    tipTx: tip_tx_raw,
                    slot: U256::from(slot),
                    sequenceNum: U256::from(sequence_number),
                    signer: preconf_request.signer,
                };

                // Decode signature
                let signature_bytes = match hex::decode(&challenge.preconf_request_signature) {
                    Ok(bytes) => Bytes::from(bytes),
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to decode signature: {}", e);
                        continue;
                    }
                };

                // Submit challenge to the contract
                debug!("[Challenger Submitter]: Submitting challenge type A for slot {}", slot);
                match taiyi_challenger
                    .createChallengeAType(preconf_request_a_type, signature_bytes)
                    .send()
                    .await
                {
                    Ok(tx) => {
                        debug!("[Challenger Submitter]: Challenge type A submitted. TX: {:?}", tx);
                    }
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to create challenge type A: {}", e);
                        // Continue to next challenge, we may be able to submit others
                    }
                }
            } else {
                // Type B
                let preconf_request =
                    match serde_json::from_str::<PreconfRequestTypeB>(&challenge.preconf_request) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(
                                "[Challenger Submitter]: Failed to parse PreconfRequestTypeB: {}",
                                e
                            );
                            continue;
                        }
                    };

                let transaction = match &preconf_request.transaction {
                    Some(tx) => tx,
                    None => {
                        error!(
                            "[Challenger Submitter]: Missing transaction in PreconfRequestTypeB"
                        );
                        continue;
                    }
                };

                let mut tx_bytes = Vec::new();
                transaction.encode_2718(&mut tx_bytes);
                let tx_raw = format!("0x{}", hex::encode(&tx_bytes));

                let preconf_request_b_type = TaiyiInteractiveChallenger::PreconfRequestBType {
                    blockspaceAllocation: TaiyiInteractiveChallenger::BlockspaceAllocation {
                        gasLimit: U256::from(preconf_request.allocation.gas_limit),
                        sender: preconf_request.allocation.sender,
                        recipient: preconf_request.allocation.recipient,
                        deposit: U256::from(preconf_request.allocation.deposit),
                        tip: U256::from(preconf_request.allocation.tip),
                        targetSlot: U256::from(preconf_request.allocation.target_slot),
                        blobCount: U256::from(preconf_request.allocation.blob_count),
                    },
                    blockspaceAllocationSignature: preconf_request.alloc_sig.as_bytes().into(),
                    rawTx: Bytes::from(tx_raw),
                    // TODO: Can we remove this two fields ?
                    underwriterSignedBlockspaceAllocation: Bytes::from([]),
                    underwriterSignedRawTx: Bytes::from([]),
                };

                // Decode signature
                let signature_bytes = match hex::decode(&challenge.preconf_request_signature) {
                    Ok(bytes) => Bytes::from(bytes),
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to decode signature: {}", e);
                        continue;
                    }
                };

                // Submit challenge to the contract
                debug!("[Challenger Submitter]: Submitting challenge type B for slot {}", slot);
                match taiyi_challenger
                    .createChallengeBType(preconf_request_b_type, signature_bytes)
                    .send()
                    .await
                {
                    Ok(tx) => {
                        debug!("[Challenger Submitter]: Challenge type B submitted. TX: {:?}", tx);
                    }
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to create challenge type B: {}", e);
                        // Continue to next challenge, we may be able to submit others
                    }
                }
            }
        }

        debug!("[Challenger Submitter]: Processed block {:?}", header.number);
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
        eprintln!("Failed to create preconf database: {e}");
        std::process::exit(1);
    });

    let preconf_db = Arc::new(preconf_db);

    let challenge_db = Database::create("challenge.db").unwrap_or_else(|e| {
        eprintln!("Failed to create challenge database: {e}");
        std::process::exit(1);
    });

    let challenge_db = Arc::new(challenge_db);

    // Create tables if they don't exist
    debug!("Creating tables...");

    let create_preconf_table = || -> Result<(), redb::Error> {
        let tx = preconf_db.begin_write()?;
        tx.open_table(PRECONF_TABLE)?;
        tx.commit()?;
        Ok(())
    };

    if let Err(e) = create_preconf_table() {
        error!("Failed to create preconf table: {}", e);
        return Err(eyre::eyre!("Failed to create preconf table: {}", e));
    }

    let create_challenge_table = || -> Result<(), redb::Error> {
        let tx = challenge_db.begin_write()?;
        tx.open_table(CHALLENGE_TABLE)?;
        tx.commit()?;
        Ok(())
    };

    if let Err(e) = create_challenge_table() {
        error!("Failed to create challenge table: {}", e);
        return Err(eyre::eyre!("Failed to create challenge table: {}", e));
    }

    debug!("Tables created successfully");

    // Read genesis timestamp from Beacon API (/eth/v1/beacon/genesis)
    let beacon_genesis_response = match reqwest::Client::new()
        .get(format!("{}/eth/v1/beacon/genesis", opts.beacon_url))
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to get beacon genesis: {}", e);
            return Err(eyre::eyre!("Failed to get beacon genesis: {}", e));
        }
    };

    let beacon_genesis_response = match beacon_genesis_response.json::<serde_json::Value>().await {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to parse beacon genesis response: {}", e);
            return Err(eyre::eyre!("Failed to parse beacon genesis response: {}", e));
        }
    };

    let genesis_time =
        beacon_genesis_response["data"]["genesis_time"].as_str().ok_or_else(|| {
            let err = "Failed to get genesis time from response";
            error!("{}", err);
            eyre::eyre!("{}", err)
        })?;

    let genesis_timestamp = match u64::from_str(genesis_time) {
        Ok(timestamp) => timestamp,
        Err(e) => {
            error!("Failed to parse genesis time: {}", e);
            return Err(eyre::eyre!("Failed to parse genesis time: {}", e));
        }
    };

    let mut handles = Vec::new();

    // Handles for ingesting underwriter streams
    let underwriter_stream_urls = opts.underwriter_stream_urls.clone();
    let underwriter_stream_urls = underwriter_stream_urls
        .iter()
        .filter_map(|url| match Url::parse(url) {
            Ok(parsed_url) => Some(parsed_url),
            Err(e) => {
                error!("Failed to parse URL '{}': {}", url, e);
                None
            }
        })
        .collect::<Vec<_>>();

    if underwriter_stream_urls.is_empty() {
        error!("No valid underwriter stream URLs provided");
        return Err(eyre::eyre!("No valid underwriter stream URLs provided"));
    }

    for url in underwriter_stream_urls {
        let handle = tokio::spawn(handle_underwriter_stream(preconf_db.clone(), url));
        handles.push(handle);
    }

    // Handle for creating challenges
    let challenger_creator_handle = tokio::spawn(handle_challenge_creation(
        preconf_db.clone(),
        challenge_db.clone(),
        opts.clone(),
        genesis_timestamp,
    ));

    handles.push(challenger_creator_handle);

    // Handle for submitting challenges
    let challenger_submitter_handle = tokio::spawn(handle_challenge_submission(
        challenge_db.clone(),
        opts.clone(),
        genesis_timestamp,
    ));

    handles.push(challenger_submitter_handle);

    let _ = join_all(handles).await;

    Ok(())
}
