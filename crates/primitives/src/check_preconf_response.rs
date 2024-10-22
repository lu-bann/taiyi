use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfStatusResponse {
    pub status: PreconfStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PreconfStatus {
    Accepted,
    Rejected,
    Pending,
}
