use std::time::Duration;

use crate::{
    pbs::{
        state::{BuilderApiState, PbsState},
        BUILDER_API_PATH, GET_STATUS_PATH,
    },
    types::Chain,
};
//use cb_metrics::provider::MetricsProvider;
use eyre::{bail, Context, Result};
use parking_lot::RwLock;
use prometheus::core::Collector;
use tokio::net::TcpListener;
use url::Url;

use crate::{
    pbs::api::BuilderApi,
    //    config::metrics::PBS_METRICS_REGISTRY,
    pbs::routes::create_app_router,
};

pub struct PbsService;

impl PbsService {
    pub async fn run<S: BuilderApiState, A: BuilderApi<S>>(state: PbsState<S>) -> Result<()> {
        let addr = state.config.endpoint;

        let app = create_app_router::<S, A>(RwLock::new(state).into());
        let listener = TcpListener::bind(addr).await?;

        let task =
            tokio::spawn(
                async move { axum::serve(listener, app).await.wrap_err("PBS server exited") },
            );

        // wait for the server to start
        tokio::time::sleep(Duration::from_millis(250)).await;
        let local_url =
            Url::parse(&format!("http://{}{}{}", addr, BUILDER_API_PATH, GET_STATUS_PATH))?;

        let status = reqwest::get(local_url).await?;
        if !status.status().is_success() {
            bail!("PBS server failed to start. Are the relays properly configured?");
        }

        task.await?
    }

    pub fn register_metric(_c: Box<dyn Collector>) {
        //        PBS_METRICS_REGISTRY.register(c).expect("failed to register metric");
    }

    pub fn init_metrics(_network: Chain) -> Result<()> {
        //        MetricsProvider::load_and_run(network, PBS_METRICS_REGISTRY.clone())
        Ok(())
    }
}
