use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{
    core::Collector, register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    HistogramTimer, HistogramVec, IntCounterVec, Registry,
};

use super::provider::MetricsProvider;

lazy_static! {
    pub static ref TAIYI_GATEWAY_METRICS: Registry =
        Registry::new_custom(Some("taiyi_gateway".to_string()), None)
            .expect("fail to create registry");
    static ref REQUEST_COUNTS: IntCounterVec = register_int_counter_vec_with_registry!(
        "request_count_total",
        "Count of requests",
        &["endpoint"],
        &TAIYI_GATEWAY_METRICS
    )
    .unwrap();
    static ref REQUEST_STATUS: IntCounterVec = register_int_counter_vec_with_registry!(
        "request_status_total",
        "Count of status codes",
        &["endpoint", "http_status_code"],
        &TAIYI_GATEWAY_METRICS
    )
    .unwrap();
    static ref REQUEST_LATENCY: HistogramVec = register_histogram_vec_with_registry!(
        "request_latency_sec",
        "Latency of requests",
        &["endpoint"],
        &TAIYI_GATEWAY_METRICS
    )
    .unwrap();
    static ref REQUEST_SIZE: IntCounterVec = register_int_counter_vec_with_registry!(
        "request_size_bytes",
        "Size of requests",
        &["endpoint"],
        &TAIYI_GATEWAY_METRICS
    )
    .unwrap();
}

pub struct APIMetrics;

impl APIMetrics {
    pub fn count(endpoint: &str) {
        REQUEST_COUNTS.with_label_values(&[endpoint]).inc();
    }
    pub fn status(endpoint: &str, status_code: &str) {
        REQUEST_STATUS.with_label_values(&[endpoint, status_code]).inc();
    }
    pub fn timer(endpoint: &str) -> HistogramTimer {
        REQUEST_LATENCY.with_label_values(&[endpoint]).start_timer()
    }
    pub fn size(endpoint: &str, size: usize) {
        REQUEST_SIZE.with_label_values(&[endpoint]).inc_by(size as u64);
    }
}
pub fn init_metrics(server_port: u16) -> Result<()> {
    PreconferMetricsService::init_metrics(server_port)
}

pub struct PreconferMetricsService;

impl PreconferMetricsService {
    pub fn register_metric(c: Box<dyn Collector>) {
        TAIYI_GATEWAY_METRICS.register(c).expect("failed to register metric");
    }

    pub fn init_metrics(server_port: u16) -> Result<()> {
        MetricsProvider::load_and_run(server_port, TAIYI_GATEWAY_METRICS.clone())
    }
}
