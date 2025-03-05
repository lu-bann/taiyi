mod clients;
pub mod context_ext;
mod contract;
mod error;
mod lookahead_fetcher;
pub mod metrics;
mod network_state;
mod preconf_api;
mod preconf_pool;
mod pricer;
#[cfg(test)]
mod tests;
mod validator;

pub use preconf_api::{spawn_service, state::SlotInfo};

pub const PATH_BUILDER_API: &str = "/relay/v1/builder";

pub const PATH_BUILDER_DELEGATIONS: &str = "/delegations";

pub const PATH_BUILDER_CONSTRAINTS: &str = "/constraints";

pub const PATH_CONSTRAINTS_API: &str = "/constraints/v1";

pub const PATH_SUBMIT_BUILDER_CONSTRAINTS: &str = "/builder/constraints";

pub use preconf_api::api::{
    AVAILABLE_SLOT_PATH, ESTIMATE_TIP_PATH, RESERVE_BLOCKSPACE_PATH, SUBMIT_TRANSACTION_PATH,
    SUBMIT_TYPEA_TRANSACTION_PATH,
};
