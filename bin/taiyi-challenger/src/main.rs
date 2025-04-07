use std::{collections::HashSet, sync::Arc};

use alloy_eips::{merge::SLOT_DURATION_SECS, BlockNumberOrTag};
use alloy_primitives::{hex, Address};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_signer::k256::{self};
use alloy_sol_types::sol;
use clap::Parser;
use futures_util::StreamExt;
use redb::{Database, TableDefinition};
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};
use tracing::info;

mod preconf_request_data;
use preconf_request_data::{Bincode, PreconfRequestData};

// TODO: Change to use correct types
const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("preconf");
const CHALLENGE_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("challenge");

// TODO: Read from context ?
const GENESIS_TIMESTAMP: u64 = 1_655_733_600;

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

#[derive(Parser, Clone)]
struct Opts {
    /// execution_client_url
    #[clap(long = "execution_client_url", default_value = "http://localhost:63970")]
    execution_client_url: String,
    /// execution_client_url
    #[clap(long = "execution_client_ws_url", default_value = "ws://localhost:63971")]
    execution_client_ws_url: String,
    /// finalization_window
    #[clap(long = "finalization_window", default_value = "32")]
    finalization_window: u64,

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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Read cli args
    let opts = Opts::parse();
    let execution_client_ws_url = opts.execution_client_ws_url.clone();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // 4. Initialize signer
    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
        k256::ecdsa::SigningKey::from_slice(&hex::decode(
            opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key),
        )?)?,
    );

    info!("Signer address: {}", private_key_signer.address());

    // let taiyi_escrow =
    //     TaiyiInteractiveChallenger::new(opts.taiyi_challenger_address, provider.clone());

    // 5. Initialize contract
    // 6. Initialize database for storing preconfirmations
    let preconf_db = Database::create("preconf.db").unwrap_or_else(|e| {
        eprintln!("Failed to create preconf database: {}", e);
        std::process::exit(1);
    });

    let preconf_db = Arc::new(preconf_db);

    // 7. Initialize database for storing challenges
    let challenge_db = Database::create("challenge.db").unwrap_or_else(|e| {
        eprintln!("Failed to create challenge database: {}", e);
        std::process::exit(1);
    });

    let challenge_db = Arc::new(challenge_db);

    // TODO: Preconfirmation ingestor
    // 1. Read/Listen to preconfirmation streams for each provided underwriter address
    // 2. For each preconfirmation store it in the kv db (key: slot/block_number, value: preconfirmation + other necessary data)

    let challenger_creator_handle = tokio::spawn(async move {
        // Create a ws provider
        let ws = WsConnect::new(opts.execution_client_ws_url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await.unwrap();

        // Subscribe to block headers.
        let subscription = provider.subscribe_blocks().await.unwrap();
        let mut stream = subscription.into_stream();

        while let Some(header) = stream.next().await {
            info!("Processing block {:?}", header.number);
            let slot = get_slot_from_timestamp(header.timestamp, GENESIS_TIMESTAMP);
            info!("Slot: {:?}", slot);

            // Check if preconfirmations exists for the slot
            let read_tx = preconf_db.begin_read().unwrap();
            let table = read_tx.open_table(PRECONF_TABLE).unwrap();
            let preconfs = table.get(&slot);

            if preconfs.is_err() {
                // Storage error
                info!("Storage error for slot {}. Error: {:?}", slot, preconfs.err());
                continue;
            }

            let preconfs = preconfs.unwrap();

            if preconfs.is_none() {
                // No preconfirmation found for the slot
                continue;
            }

            let preconfs = preconfs.unwrap().value();

            info!("Found {} preconfirmations for slot {}", preconfs.len(), slot);

            let block = provider.get_block_by_number(BlockNumberOrTag::Number(header.number)).await;

            if block.is_err() {
                // RPC error
                info!("RPC error for block {}. Error: {:?}", header.number, block.err());
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
                        serde_json::from_str::<PreconfRequestTypeA>(&preconf.preconf_request)
                            .unwrap();
                    let mut open_challenge = false;

                    // Check if all user txs are included in the block
                    if !preconf_request.preconf_tx.iter().all(|tx| tx_hashes.contains(tx.tx_hash()))
                    {
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
                        serde_json::from_str::<PreconfRequestTypeB>(&preconf.preconf_request)
                            .unwrap();

                    // Check if all user txs are included in the block
                    if !tx_hashes.contains(preconf_request.transaction.unwrap().tx_hash()) {
                        // TODO: Create a challenge
                    }
                }
            }

            info!("Processed block {:?}", header.number);
        }
    });

    let challenger_submitter_handle = tokio::spawn(async move {
        // TODO: Challenger submitter
        // 1. Read/Listen to latest block from provider
        // 2. Check challenge db for challenges for the specific slot
        // 3. Submit challenge to the network

        let ws = WsConnect::new(execution_client_ws_url);
        let provider = ProviderBuilder::new().on_ws(ws).await.unwrap();
        let taiyi_challenger =
            TaiyiInteractiveChallenger::new(opts.taiyi_challenger_address, provider.clone());

        let subscription = provider.subscribe_blocks().await.unwrap();
        let mut stream = subscription.into_stream();

        while let Some(header) = stream.next().await {
            info!("Processing block {:?}", header.number);
            let slot = get_slot_from_timestamp(header.timestamp, GENESIS_TIMESTAMP);
            info!("Slot: {:?}", slot);

            // Check if challenges exists for the slot
            let read_tx = challenge_db.begin_read().unwrap();
            let table = read_tx.open_table(CHALLENGE_TABLE).unwrap();
            let challenges = table.get(&slot);

            if challenges.is_err() {
                // Storage error
                info!("Storage error for slot {}. Error: {:?}", slot, challenges.err());
                continue;
            }

            let challenges = challenges.unwrap();

            if challenges.is_none() {
                // No challenges found for the slot
                info!("No challenges found for slot {}", slot);
                continue;
            }

            let challenges = challenges.unwrap().value();

            // For each challenge, check if the challenge is expired
            for challenge in challenges {
                // TODO: Open challanges on-chan
                if challenge.preconf_type == 0 {
                    // Type A
                    // taiyi_challenger.createChallengeAType().await;
                } else {
                    // Type B
                }
            }

            info!("Processed block {:?}", header.number);
        }
    });

    let _ = tokio::join!(challenger_creator_handle, challenger_submitter_handle);

    Ok(())
}
