use builder::{SidecarBuilderApi, SidecarBuilderState};
use clap::Parser;
use commit_boost::prelude::{load_pbs_custom_config, PbsService, PbsState};
use constraints::subscribe_to_constraints_stream;
use eyre::Result;
use taiyi_cmd::initialize_tracing_log;
use types::ExtraConfig;

mod block_builder;
mod builder;
mod constraints;
mod engine;
mod engine_hinter;
mod error;
mod execution;
mod ext;
mod metrics;
mod proofs;
mod types;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, _) = load_pbs_custom_config::<()>().await?;
    initialize_tracing_log();

    let opts = Opts::parse();
    let config = ExtraConfig {
        engine_api: opts.engine_api.parse()?,
        execution_api: opts.execution_api.parse()?,
        beacon_api: opts.beacon_api.parse()?,
        fee_recipient: opts.fee_recipient.parse()?,
        builder_private_key: opts.builder_private_key.as_str().into(),
        engine_jwt: opts.engine_jwt.as_str().try_into()?,
        network: opts.network.into(),
        auth_token: opts.auth_token,
    };

    let sidecar_state = SidecarBuilderState::new(&config).await;
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state.clone());

    subscribe_to_constraints_stream(sidecar_state.constraints.clone(), pbs_state.all_relays())
        .await?;

    metrics::init_metrics(pbs_config.chain)?;

    PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state).await?;

    Ok(())
}

#[derive(Parser)]
struct Opts {
    #[clap(long = "execution_api", default_value = "http://localhost:8545")]
    execution_api: String,

    #[clap(long = "beacon_api", default_value = "http://localhost:5062")]
    beacon_api: String,

    #[clap(long = "engine_api", default_value = "http://localhost:8551")]
    engine_api: String,

    #[clap(long = "builder_private_key")]
    builder_private_key: String,

    #[clap(long = "network")]
    network: String,

    #[clap(long = "fee_recipient")]
    fee_recipient: String,

    #[clap(long = "engine_jwt")]
    engine_jwt: String,

    #[clap(long = "auth_token")]
    auth_token: Option<String>,
}
