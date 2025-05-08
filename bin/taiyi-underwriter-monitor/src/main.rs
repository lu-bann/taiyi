mod database;

use alloy_eips::{merge::SLOT_DURATION_SECS, BlockId, BlockNumberOrTag};
use alloy_primitives::map::HashSet;
use alloy_provider::{Provider as _, ProviderBuilder, WsConnect};
use alloy_rpc_types::Block;
use clap::Parser;
use database::{get_db_connection, u128_to_big_decimal, TaiyiDBConnection, UnderwriterTradeRow};
use ethereum_consensus::{deneb::Context, networks::Network};
use futures_util::StreamExt as _;
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use std::process::exit;
use taiyi_primitives::{PreconfRequest, PreconfResponseData};
use tracing::{debug, error};

const MIN_BASE_FEE_PER_BLOB_GAS: u64 = 1;
const BLOB_BASE_FEE_UPDATE_FRACTION: u64 = 3338477;

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

/// Listens on Taiyi's SSE stream of commitments, and inserts rows which represent the beginning
/// of an underwriter trade
async fn commitment_stream_listener(db_conn: TaiyiDBConnection, url: Url) -> eyre::Result<()> {
    let req = reqwest::Client::new().get(url);

    let mut event_source = EventSource::new(req).unwrap_or_else(|err| {
        panic!("Failed to create EventSource: {err:?}");
    });

    while let Some(event) = event_source.next().await {
        match event {
            Ok(Event::Message(message)) => {
                let data = &message.data;

                let parsed_data =
                    serde_json::from_str::<Vec<(PreconfRequest, PreconfResponseData)>>(data)?;

                debug!("[Stream Ingestor]: Received {} preconfirmations", parsed_data.len());

                for (preconf_request, preconf_response_data) in parsed_data.iter() {
                    let target_slot = preconf_request.target_slot();
                    debug!("[Stream Ingestor]: Processing preconfirmation for slot {target_slot}");
                    let row = UnderwriterTradeRow::try_from_preconf_request(
                        preconf_response_data.current_slot,
                        preconf_response_data.request_id,
                        preconf_request,
                    )?;
                    row.insert_trade_initiation_into_db(&db_conn).await?;
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

async fn tx_settlement_listener(
    execution_client_ws_url: String,
    genesis_timestamp: u64,
    db_conn: TaiyiDBConnection,
) -> eyre::Result<()> {
    // Create a ws provider
    let ws = WsConnect::new(execution_client_ws_url);
    let provider = match ProviderBuilder::new().on_ws(ws).await {
        Ok(provider) => provider,
        Err(e) => {
            error!("[Settlement Monitor]: Failed to create provider: {}", e);
            return Err(eyre::eyre!("Failed to create provider: {}", e));
        }
    };

    // Subscribe to block headers.
    let subscription = match provider.subscribe_blocks().await {
        Ok(sub) => sub,
        Err(e) => {
            error!("[Settlement Monitor]: Failed to subscribe to blocks: {}", e);
            return Err(eyre::eyre!("Failed to subscribe to blocks: {}", e));
        }
    };
    let mut stream = subscription.into_stream();

    while let Some(header) = stream.next().await {
        debug!("[Settlement Monitor]: Processing block {:?}", header.number);
        let slot = get_slot_from_timestamp(header.timestamp, genesis_timestamp);
        debug!("[Settlement Monitor]: Slot: {:?}", slot);

        let block =
            match provider.get_block_by_number(BlockNumberOrTag::Number(header.number)).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("[Settlement Monitor]: Block {} not found", header.number);
                    continue;
                }
                Err(e) => {
                    // RPC error
                    error!(
                        "[Settlement Monitor]: RPC error for block {}. Error: {:?}",
                        header.number, e
                    );
                    continue;
                }
            };
        let receipts = provider
            .get_block_receipts(BlockId::number(block.header.number))
            .await?
            .expect("no block receipts?");

        let tx_hashes = block.transactions.hashes().collect::<HashSet<_>>();

        let preconfs = UnderwriterTradeRow::find_all_by_slot(slot, &db_conn).await?;

        let realized_blob_price = get_blob_gas_price(&block);

        // For each preconfirmation, check if the required txs are included in the block
        for preconf in preconfs {
            let preconf_type = preconf.preconf_type;

            assert!(!preconf.settled, "preconf should not be settled. Preconf: {preconf:?}");
            assert!(
                preconf.realized_gas_price.is_none(),
                "preconf should not be have realized_gas_price. Preconf: {preconf:?}"
            );
            assert!(
                preconf.realized_blob_price.is_none(),
                "preconf should not be have realized_blob_price. Preconf: {preconf:?}"
            );

            // Check if all user txs are included in the block
            if !preconf.tx_hashes.iter().all(|tx_hash| tx_hashes.contains(tx_hash)) {
                error!(
                    "error: preconf tx with uuid {} was not completely \
                       included in the block number {}. Tx: {:?}",
                    preconf.uuid, header.number, preconf
                );
                continue;
            }
            let realized_gas_price = {
                let prices = receipts
                    .iter()
                    .filter_map(|receipt| {
                        if preconf.tx_hashes.iter().all(|y| y != receipt.transaction_hash) {
                            None
                        } else {
                            Some(receipt.effective_gas_price)
                        }
                    })
                    .collect::<Vec<_>>();
                let first_elem = prices.first().expect("bug, should have at least one hash");
                if preconf_type == 0 {
                    // Type A
                    assert!(
                        prices.iter().all(|x| x == first_elem),
                        "type a bug: all transactions should have same gas price"
                    );
                } else {
                    // Type B
                    assert!(prices.len() == 1, "type b bug: there shouldn't be more than one tx");
                }
                *first_elem
            };

            UnderwriterTradeRow::update_with_settlement(
                preconf.uuid,
                u128_to_big_decimal(realized_gas_price)?,
                realized_blob_price.and_then(|x| u128_to_big_decimal(x).ok()),
                &db_conn,
            )
            .await?;
        }

        debug!("[Settlement Monitor]: Processed block {:?}", header.number);
    }

    Ok(())
}

fn get_blob_gas_price(data: &Block) -> Option<u128> {
    // adapted from https://eips.ethereum.org/EIPS/eip-4844#gas-accounting
    let excess_blob_gas = data.header.excess_blob_gas? as f64;
    let base_fee_per_blob_gas = MIN_BASE_FEE_PER_BLOB_GAS as f64
        * (excess_blob_gas / BLOB_BASE_FEE_UPDATE_FRACTION as f64).exp();
    Some(base_fee_per_blob_gas as u128)
}

#[derive(Parser, Clone)]
struct Opts {
    #[clap(long)]
    execution_client_ws_url: String,

    #[clap(long)]
    pub network: String,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> eyre::Result<()> {
    let opts = Opts::parse();

    let db_conn = get_db_connection("postgres:///admin:password@127.0.0.1:5432/test_db").await?;
    UnderwriterTradeRow::init_db_schema(&db_conn).await?;
    let commitment_handle = commitment_stream_listener(
        db_conn.clone(),
        Url::parse("http://127.0.0.1:5656/commitments/v0/commitment_stream")?,
    );
    let genesis_time = {
        let network: Network = opts.network.clone().into();
        let context: Context = network.try_into()?;
        context.genesis_time()?
    };
    let tx_settlement_handle =
        tx_settlement_listener(opts.execution_client_ws_url, genesis_time, db_conn);
    tokio::select! {
        result = commitment_handle => {
            error!("commitment listener task is dead. exiting...");
            match result {
                Ok(_) => {},
                Err(e) => {
                    error!("error on commitment task: {e}")
                }
            }
            exit(1)
        },
        result = tx_settlement_handle => {
            error!("tx settlement listener task is dead. exiting...");
            match result {
                Ok(_) => {},
                Err(e) => {
                    error!("error on tx settlement task: {e}")
                }
            }
            exit(1)
        }
    };
}
