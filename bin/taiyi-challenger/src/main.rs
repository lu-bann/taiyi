use std::{collections::HashSet, sync::Arc};

use alloy_eips::{eip2718::Encodable2718, merge::SLOT_DURATION_SECS, BlockNumberOrTag};
use alloy_primitives::{hex, Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_signer::k256::{self};
use alloy_sol_types::sol;
use clap::Parser;
use futures_util::{future::join_all, StreamExt};
use redb::{Database, TableDefinition};
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};
use tracing::{info, level_filters::LevelFilter};

mod preconf_request_data;
use preconf_request_data::{Bincode, PreconfRequestData};

const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("preconf");
const CHALLENGE_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("challenge");

// TODO: Read from context ?
const GENESIS_TIMESTAMP: u64 = 1744102518;

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

#[derive(Parser, Clone)]
struct Opts {
    /// execution_client_ws_url
    #[clap(long = "execution_client_ws_url", default_value = "ws://localhost:54488")]
    execution_client_ws_url: String,
    /// finalization_window
    #[clap(long = "finalization_window", default_value = "32")]
    finalization_window: u64,
    /// underwriter stream urls
    #[clap(long = "underwriter_stream_urls", default_value = "1, 2, 3")]
    underwriter_stream_urls: Vec<String>,
    /// Private key to sign transactions
    #[clap(long = "private_key")]
    private_key: String,
    /// Taiyi challenger contract address
    #[clap(long = "taiyi_challenger_address")]
    taiyi_challenger_address: Address,
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

async fn handle_underwriter_stream(preconf_db: Arc<Database>, opts: Arc<Opts>) -> eyre::Result<()> {
    // TODO: Implement underwriter stream ingestion
    let write_tx = preconf_db.begin_write().unwrap();
    {
        let mut table = write_tx.open_table(PRECONF_TABLE).unwrap();
        table.insert(&0, vec![]).unwrap();
    }
    write_tx.commit().unwrap();

    Ok(())
}

async fn handle_challenge_creation(
    preconf_db: Arc<Database>,
    challenge_db: Arc<Database>,
    opts: Arc<Opts>,
) -> eyre::Result<()> {
    // Create a ws provider
    let ws = WsConnect::new(opts.execution_client_ws_url.clone());
    let provider = ProviderBuilder::new().on_ws(ws).await.unwrap();

    // Subscribe to block headers.
    let subscription = provider.subscribe_blocks().await.unwrap();
    let mut stream = subscription.into_stream();

    while let Some(header) = stream.next().await {
        info!("[Challenger Creator]: Processing block {:?}", header.number);
        let slot = get_slot_from_timestamp(header.timestamp, GENESIS_TIMESTAMP);
        info!("[Challenger Creator]: Slot: {:?}", slot);

        // Check if preconfirmations exists for the slot
        let read_tx = preconf_db.begin_read().unwrap();
        let table = read_tx.open_table(PRECONF_TABLE).unwrap();
        let preconfs = table.get(&slot);

        if preconfs.is_err() {
            // Storage error
            info!(
                "[Challenger Creator]: Storage error for slot {}. Error: {:?}",
                slot,
                preconfs.err()
            );
            continue;
        }

        let preconfs = preconfs.unwrap();

        if preconfs.is_none() {
            // No preconfirmation found for the slot
            info!("[Challenger Creator]: No preconfirmations found for slot {}", slot);
            continue;
        }

        let preconfs = preconfs.unwrap().value();

        info!("[Challenger Creator]: Found {} preconfirmations for slot {}", preconfs.len(), slot);

        let block = provider.get_block_by_number(BlockNumberOrTag::Number(header.number)).await;

        if block.is_err() {
            // RPC error
            info!(
                "[Challenger Creator]: RPC error for block {}. Error: {:?}",
                header.number,
                block.err()
            );
            continue;
        }

        let block = block.unwrap().unwrap();
        let tx_hashes = block.transactions.hashes().collect::<HashSet<_>>();

        // Calculate the challenge submission slot. We need to wait for the block to be finalized
        // before we can open a challenge.
        let challenge_submission_slot = slot + opts.finalization_window;

        // For each preconfirmation, check if the required txs are included in the block
        for preconf in preconfs {
            let preconf_type = preconf.preconf_type;
            let preconf_request_signature = preconf.preconf_request_signature;

            if preconf_type == 0 {
                // Type A
                let preconf_request =
                    serde_json::from_str::<PreconfRequestTypeA>(&preconf.preconf_request).unwrap();
                let mut open_challenge = false;

                // Check if all user txs are included in the block
                if !preconf_request.preconf_tx.iter().all(|tx| tx_hashes.contains(tx.tx_hash())) {
                    open_challenge = true;
                }

                // Check if tip transaction is included in the block
                if !tx_hashes.contains(preconf_request.tip_transaction.tx_hash()) {
                    open_challenge = true;
                }

                if open_challenge {
                    // TODO: Create a challenge
                }
            } else {
                // Type B
                let preconf_request =
                    serde_json::from_str::<PreconfRequestTypeB>(&preconf.preconf_request).unwrap();

                // Check if all user txs are included in the block
                if !tx_hashes.contains(preconf_request.transaction.unwrap().tx_hash()) {
                    // TODO: Create a challenge
                }
            }
        }

        info!("[Challenger Creator]: Processed block {:?}", header.number);
    }

    Ok(())
}

async fn handle_challenge_submission(
    preconf_db: Arc<Database>,
    challenge_db: Arc<Database>,
    opts: Arc<Opts>,
) -> eyre::Result<()> {
    // Initialize signer
    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
        k256::ecdsa::SigningKey::from_slice(
            &hex::decode(opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key)).unwrap(),
        )
        .unwrap(),
    );
    let signer_address = private_key_signer.address();

    info!("[Challenger Submitter]: Signer address: {}", signer_address);

    let ws = WsConnect::new(opts.execution_client_ws_url.clone());

    let provider = ProviderBuilder::new().wallet(private_key_signer).on_ws(ws).await.unwrap();
    info!(
        "[Challenger Submitter]: Signer ETH balance: {}",
        provider.get_balance(signer_address).await.unwrap()
    );

    let taiyi_challenger =
        TaiyiInteractiveChallenger::new(opts.taiyi_challenger_address, provider.clone());

    let subscription = provider.subscribe_blocks().await.unwrap();
    let mut stream = subscription.into_stream();

    while let Some(header) = stream.next().await {
        info!("[Challenger Submitter]: Processing block {:?}", header.number);
        let slot = get_slot_from_timestamp(header.timestamp, GENESIS_TIMESTAMP);
        info!("[Challenger Submitter]: Slot: {:?}", slot);
        info!(
            "[Challenger Submitter]: Signer ETH balance: {}",
            provider.get_balance(signer_address).await.unwrap()
        );

        // Check if challenges exists for the slot
        let read_tx = challenge_db.begin_read().unwrap();
        let table = read_tx.open_table(CHALLENGE_TABLE).unwrap();
        let challenges = table.get(&slot);

        if challenges.is_err() {
            // Storage error
            info!(
                "[Challenger Submitter]: Storage error for slot {}. Error: {:?}",
                slot,
                challenges.err()
            );
            continue;
        }

        let challenges = challenges.unwrap();

        if challenges.is_none() {
            // No challenges found for the slot
            info!("[Challenger Submitter]: No challenges found for slot {}", slot);
            continue;
        }

        let challenges = challenges.unwrap().value();
        info!("[Challenger Submitter]: Found {} challenges for slot {}", challenges.len(), slot);

        // For each challenge, check if the challenge is expired
        for challenge in challenges {
            // TODO: Open challanges on-chan
            if challenge.preconf_type == 0 {
                // Type A
                let preconf_request =
                    serde_json::from_str::<PreconfRequestTypeA>(&challenge.preconf_request)
                        .unwrap();

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

                let preconf_request_a_type = TaiyiInteractiveChallenger::PreconfRequestAType {
                    txs,
                    tipTx: tip_tx_raw,
                    slot: U256::from(slot),
                    sequenceNum: U256::from(preconf_request.sequence_number.unwrap()),
                    signer: preconf_request.signer,
                };

                // TODO: Check types here (hex encoding or not...)
                let signature_bytes =
                    Bytes::from(hex::decode(challenge.preconf_request_signature).unwrap());

                // TODO: Should we watch/wait for the transaction here ?
                // TODO: Maybe store this in a Vec<_> and wait for them separately ?
                let _ = taiyi_challenger
                    .createChallengeAType(preconf_request_a_type, signature_bytes)
                    .send()
                    .await
                    .unwrap();
            } else {
                // Type B
                // TODO: Maybe I will already get the `TaiyiInteractiveChallenger::PreconfRequestBType` type here`
                let preconf_request =
                    serde_json::from_str::<PreconfRequestTypeB>(&challenge.preconf_request)
                        .unwrap();

                let mut tx = Vec::new();
                preconf_request.transaction.unwrap().encode_2718(&mut tx);
                let tx_raw = format!("0x{}", hex::encode(&tx));

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
                    blockspaceAllocationSignature:
                        // TODO: Maybe we need to hex encode this ?
                        preconf_request.alloc_sig.as_bytes().into()
                    ,
                    rawTx: Bytes::from(tx_raw),
                    underwriterSignedBlockspaceAllocation: Bytes::from([]),
                    // TODO: Maybe we need to chage the `rawTx` type to String
                    underwriterSignedRawTx: Bytes::from([]),
                };

                let signature_bytes =
                    Bytes::from(hex::decode(challenge.preconf_request_signature).unwrap());

                let _ = taiyi_challenger
                    .createChallengeBType(preconf_request_b_type, signature_bytes)
                    .send()
                    .await
                    .unwrap();
            }
        }

        info!("[Challenger Submitter]: Processed block {:?}", header.number);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Read cli args
    let opts = Opts::parse();
    let opts = Arc::new(opts);

    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(LevelFilter::INFO).init();

    let preconf_db = Database::create("preconf.db").unwrap_or_else(|e| {
        eprintln!("Failed to create preconf database: {}", e);
        std::process::exit(1);
    });

    let preconf_db = Arc::new(preconf_db);

    let challenge_db = Database::create("challenge.db").unwrap_or_else(|e| {
        eprintln!("Failed to create challenge database: {}", e);
        std::process::exit(1);
    });

    let challenge_db = Arc::new(challenge_db);

    // Create tables if they don't exist
    info!("Creating tables...");
    let tx = preconf_db.begin_write().unwrap();
    tx.open_table(PRECONF_TABLE).unwrap();
    tx.commit().unwrap();

    let tx = challenge_db.begin_write().unwrap();
    tx.open_table(CHALLENGE_TABLE).unwrap();
    tx.commit().unwrap();
    info!("Tables created successfully");

    let mut handles = Vec::new();

    // Handles for ingesting underwriter streams
    let underwriter_stream_urls = opts.underwriter_stream_urls.clone();

    for url in underwriter_stream_urls {
        let handle = tokio::spawn(handle_underwriter_stream(preconf_db.clone(), opts.clone()));
        handles.push(handle);
    }

    // Handle for creating challenges
    let challenger_creator_handle = tokio::spawn(handle_challenge_creation(
        preconf_db.clone(),
        challenge_db.clone(),
        opts.clone(),
    ));

    handles.push(challenger_creator_handle);

    // Handle for submitting challenges
    let challenger_submitter_handle = tokio::spawn(handle_challenge_submission(
        preconf_db.clone(),
        challenge_db.clone(),
        opts.clone(),
    ));

    handles.push(challenger_submitter_handle);

    let _ = join_all(handles).await;

    Ok(())
}
