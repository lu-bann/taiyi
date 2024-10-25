use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{
    core::Collector, register_int_counter_vec_with_registry, IntCounterVec, Registry,
};

use super::provider::MetricsProvider;

lazy_static! {
    pub static ref TAIYI_PRECONFER_METRICS: Registry =
        Registry::new_custom(Some("taiyi_preconfer".to_string()), None)
            .expect("fail to create registry");
    pub static ref RELAY_STATUS_CODE: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_status_code_total",
        "HTTP status code received by relay",
        &["http_status_code", "endpoint", "relay_id"],
        TAIYI_PRECONFER_METRICS
    )
    .unwrap();
}

pub fn init_metrics(server_port: u16) -> Result<()> {
    PreconferMetricsService::register_metric(Box::new(RELAY_STATUS_CODE.clone()));
    PreconferMetricsService::init_metrics(server_port)
}

pub struct PreconferMetricsService;

impl PreconferMetricsService {
    pub fn register_metric(c: Box<dyn Collector>) {
        TAIYI_PRECONFER_METRICS.register(c).expect("failed to register metric");
    }

    pub fn init_metrics(server_port: u16) -> Result<()> {
        MetricsProvider::load_and_run(server_port, TAIYI_PRECONFER_METRICS.clone())
    }
}
