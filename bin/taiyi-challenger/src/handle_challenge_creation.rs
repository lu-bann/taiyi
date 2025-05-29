use std::{collections::HashSet, sync::Arc};

use alloy_eips::BlockNumberOrTag;
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use futures_util::StreamExt;
use redb::Database;
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};
use tracing::{debug, error};

use crate::{
    get_slot_from_timestamp,
    preconf_request_data::PreconfRequestData,
    table_definitions::{CHALLENGE_TABLE, PRECONF_TABLE},
    Opts,
};

/// Store a challenge in the database for a given slot
fn store_challenge(
    challenge_db: &Database,
    submission_slot: u64,
    preconf: PreconfRequestData,
) -> Result<(), redb::Error> {
    let read_tx = challenge_db.begin_read()?;

    let table = read_tx.open_table(CHALLENGE_TABLE)?;

    // Get existing challenges or create a new vec
    let mut challenges_data = match table.get(&submission_slot)? {
        Some(val) => val.value(),
        None => Vec::new(),
    };

    // Add the new preconf
    challenges_data.push(preconf);

    // Write the updated challenges
    let write_tx = challenge_db.begin_write()?;
    {
        let mut table = write_tx.open_table(CHALLENGE_TABLE)?;
        table.insert(&submission_slot, challenges_data)?;
    }
    write_tx.commit()?;

    Ok(())
}

pub async fn handle_challenge_creation(
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
    let subscription = provider.subscribe_blocks().await?;
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

        let preconfs = match table.get(&slot) {
            Ok(Some(val)) => val.value(),
            Ok(None) => {
                debug!("[Challenger Creator]: No preconfirmations found for slot {}", slot);
                continue;
            }
            Err(e) => {
                error!("[Challenger Creator]: Storage error for slot {}. Error: {:?}", slot, e);
                continue;
            }
        };

        debug!("[Challenger Creator]: Found {} preconfirmations for slot {}", preconfs.len(), slot);

        let block =
            match provider.get_block_by_number(BlockNumberOrTag::Number(header.number)).await {
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

                // Check if all user txs are included in the block and if the tip transaction is included in the block
                if !preconf_request.preconf_tx.iter().all(|tx| tx_hashes.contains(tx.tx_hash()))
                    || !tx_hashes.contains(preconf_request.tip_transaction.tx_hash())
                {
                    open_challenge = true;
                }

                if open_challenge || opts.always_open_challenges {
                    if let Err(e) =
                        store_challenge(&challenge_db, challenge_submission_slot, preconf)
                    {
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
                    if let Err(e) = store_challenge(&challenge_db, slot, preconf) {
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
