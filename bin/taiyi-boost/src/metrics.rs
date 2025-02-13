use commit_boost::prelude::*;
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry, IntCounterVec,
    IntGaugeVec, Registry,
};

pub fn init_metrics(chain: Chain) -> Result<()> {
    PbsService::register_metric(Box::new(PRECONFER_SLOT.clone()));
    PbsService::register_metric(Box::new(BEACON_NODE_LATEST_SLOT.clone()));
    PbsService::register_metric(Box::new(DELEGATION_FAIL_SLOT.clone()));
    PbsService::register_metric(Box::new(DELEGATION_SUCCESS_VALIDATORS.clone()));

    PbsService::init_metrics(chain)
}

lazy_static! {
    pub static ref TAIYI_BOOST_METRICS: Registry =
        Registry::new_custom(Some("taiyi_boost".to_string()), None).expect("fail to create registry");

    /// Preconfer slot for which our validator has the right to propose a block
    pub static ref PRECONFER_SLOT: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "preconfer_slot",
        "Preconfer slot for which our validator has the right to propose a block",
        &["epoch_id"],
        TAIYI_BOOST_METRICS
    )
    .unwrap();

    pub static ref BEACON_NODE_LATEST_SLOT: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "beacon_node_latest_slot",
        "The latest slot of the beacon node",
        &["beacon_node"],
        TAIYI_BOOST_METRICS
    )
    .unwrap();

    pub static ref DELEGATION_FAIL_SLOT: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "delegation_fail_slot",
        "Slot for which delegation failed",
        &["epoch_id"],
        TAIYI_BOOST_METRICS
    )
    .unwrap();

    pub static ref DELEGATION_SUCCESS_VALIDATORS: IntCounterVec = register_int_counter_vec_with_registry!(
        "delegation_success_validators",
        "Number of validators successfully delegated",
        &["validator_pubkey", "validator_index"],
        TAIYI_BOOST_METRICS
    )
    .unwrap();
}
