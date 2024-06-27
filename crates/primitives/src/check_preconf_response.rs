use serde::{Deserialize, Serialize};

use crate::PreconfRequest;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfStatusResponse {
    pub status: PreconfStatus,
    pub data: PreconfRequest,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PreconfStatus {
    Accepted,
    Rejected,
    Pending,
}
