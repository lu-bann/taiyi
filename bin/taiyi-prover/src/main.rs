use std::{str::FromStr, sync::Arc};

use alloy_eips::merge::SLOT_DURATION_SECS;
use alloy_primitives::Address;
use clap::Parser;
use futures_util::future::join_all;
use handle_underwriter_stream::handle_underwriter_stream;
use redb::Database;
use reqwest::Url;
use respond_to_challenges::respond_to_challenges;
use table_definitions::PRECONF_TABLE;
use tracing::{debug, error, level_filters::LevelFilter};

mod handle_underwriter_stream;
mod preconf_request_data;
mod respond_to_challenges;
mod table_definitions;

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
