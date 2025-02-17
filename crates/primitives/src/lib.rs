mod cancel_preconf;
mod check_preconf_response;
mod constraints;
mod context_ext;
mod preconf_fee;
mod preconf_hash;
mod preconf_request;
mod preconf_response;
mod preconf_tx;
mod preconf_tx_request;
mod proposer_info;

pub use cancel_preconf::{CancelPreconfRequest, CancelPreconfResponse};
pub use check_preconf_response::{PreconfStatus, PreconfStatusResponse};
pub use constraints::{ConstraintsMessage, SignableBLS, SignedConstraints};
pub use context_ext::ContextExt;
pub use preconf_fee::PreconfFeeResponse;
pub use preconf_hash::PreconfHash;
pub use preconf_request::{BlockspaceAllocation, PreconfRequest, SubmitTransactionRequest};
pub use preconf_response::PreconfResponse;
pub use preconf_tx::PreconfTx;
pub use preconf_tx_request::PreconfTxRequest;
pub use proposer_info::ProposerInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SlotInfo {
    pub slot: u64,
    pub gas_available: u64,
    pub blobs_available: usize,
    pub constraints_available: u32,
}
