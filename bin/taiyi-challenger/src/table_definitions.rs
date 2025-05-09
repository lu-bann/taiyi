use redb::TableDefinition;

use crate::preconf_request_data::{Bincode, PreconfRequestData};

pub const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("preconf");
pub const CHALLENGE_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("challenge");
