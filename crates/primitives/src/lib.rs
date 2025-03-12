mod constraints;
mod preconf_fee;
mod preconf_request_type_b;
mod preconf_response;
mod tx_ext;

pub use constraints::{ConstraintsMessage, SignableBLS, SignedConstraints};
pub use preconf_fee::PreconfFeeResponse;
pub use preconf_request_type_b::{BlockspaceAllocation, PreconfRequest, SubmitTransactionRequest};
pub use preconf_response::{PreconfResponse, PreconfResponseData};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SlotInfo {
    pub slot: u64,
    pub gas_available: u64,
    pub blobs_available: usize,
    pub constraints_available: u32,
}
pub use tx_ext::TxExt;
