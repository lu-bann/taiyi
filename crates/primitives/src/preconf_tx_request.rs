use serde::{Deserialize, Serialize};

use crate::{PreconfHash, PreconfTx};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfTxRequest {
    pub preconf_hash: PreconfHash,
    pub tx: PreconfTx,
}
