use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{
    core::Collector, register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    HistogramVec, IntCounterVec, Registry,
};

use super::provider::MetricsProvider;

lazy_static! {
    pub static ref TAIYI_PRECONFER_METRICS: Registry =
        Registry::new_custom(Some("taiyi_preconfer".to_string()), None)
            .expect("fail to create registry");
    pub static ref RELAY_STATUS_CODE: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_status_code_total",
        "HTTP status code received by relay",
        &["http_status_code", "endpoint"],
        TAIYI_PRECONFER_METRICS
    )
    .unwrap();
    pub static ref BLOCKSPACE_REQUEST_RECEIVED: IntCounterVec =
        register_int_counter_vec_with_registry!(
            "preconf_request_received",
            "Number of preconf requests received",
            &["http_status_code", "endpoint"],
            TAIYI_PRECONFER_METRICS
        )
        .unwrap();
    pub static ref PRECONF_CANCEL_RECEIVED: IntCounterVec =
        register_int_counter_vec_with_registry!(
            "preconf_cancel_received",
            "Number of preconf cancel received",
            &["http_status_code", "endpoint"],
            TAIYI_PRECONFER_METRICS
        )
        .unwrap();
    pub static ref PRECONF_TX_RECEIVED: IntCounterVec = register_int_counter_vec_with_registry!(
        "preconf_tx_received",
        "Number of preconf tx received",
        &["http_status_code", "endpoint"],
        TAIYI_PRECONFER_METRICS
    )
    .unwrap();
    pub static ref PRECONF_CONSTRAINTS_SENT_TIME: HistogramVec =
        register_histogram_vec_with_registry!(
            "preconf_constraints_sent_time",
            "preconf constraints sent to relay timestamp",
            &["slot_id"],
            TAIYI_PRECONFER_METRICS
        )
        .unwrap();
    pub static ref PRECONF_RESPONSE_DURATION: HistogramVec = register_histogram_vec_with_registry!(
        "preconf_response_duration",
        "Duration of preconf response",
        &["http_status_code", "endpoint"],
        TAIYI_PRECONFER_METRICS
    )
    .unwrap();
}

pub fn init_metrics(server_port: u16) -> Result<()> {
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
