use redb::TableDefinition;

use crate::preconf_request_data::{Bincode, PreconfRequestData};

pub const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<String>>> =
    TableDefinition::new("preconf");

pub const PRECONF_DATA_TABLE: TableDefinition<String, Bincode<PreconfRequestData>> =
    TableDefinition::new("preconf_data");
