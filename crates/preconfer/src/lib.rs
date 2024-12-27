#![allow(unused_imports, dead_code)]

mod clients;
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

pub use preconf_api::{spawn_service, state::GetSlotResponse};

pub const PATH_BUILDER_API: &str = "/relay/v1/builder";

pub const PATH_BUILDER_DELEGATIONS: &str = "/delegations";

pub const PATH_BUILDER_CONSTRAINTS: &str = "/constraints";

pub const PATH_CONSTRAINTS_API: &str = "/constraints/v1";

pub const PATH_SUBMIT_BUILDER_CONSTRAINTS: &str = "/builder/constraints";
