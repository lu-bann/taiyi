use std::sync::Arc;

use alloy_eips::merge::SLOT_DURATION_SECS;
use alloy_primitives::Address;
use clap::Parser;
use ethereum_consensus::{deneb::Context, networks::Network};
use futures_util::future::join_all;
use handle_challenge_creation::handle_challenge_creation;
use handle_challenge_submission::handle_challenge_submission;
use handle_underwriter_stream::handle_underwriter_stream;
use redb::Database;
use reqwest::Url;
use table_definitions::{CHALLENGE_TABLE, PRECONF_TABLE};
use tracing::{debug, error, level_filters::LevelFilter};

mod handle_challenge_creation;
mod handle_challenge_submission;
mod handle_underwriter_stream;
mod preconf_request_data;
mod table_definitions;

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

#[derive(Parser, Clone)]
struct Opts {
    /// execution_client_ws_url
    #[clap(long = "execution-client-ws-url")]
    execution_client_ws_url: String,
    /// network
    #[clap(long = "network")]
    network: String,
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

    // Genesis timestamp
    let network: Network = opts.network.clone().into();
    let context: Context = network.try_into()?;
    let genesis_timestamp = context.genesis_time()?;

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
