// the code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/builder/fallback/engine_hints/mod.rs
use alloy_rpc_types_engine::ClientCode;
use tracing::error;

use super::EngineApiHint;
use crate::error::BuilderError;

/// Parse engine hints from Geth execution clients.
mod geth;

/// Tries to parse engine hints from the given execution client and error response.
///
/// * Returns Ok(None) if no hint could be parsed.
/// * Returns an error if the execution client is not supported.
pub fn parse_hint_from_engine_response(
    client: ClientCode,
    error: &str,
) -> Result<Option<EngineApiHint>, BuilderError> {
    match client {
        ClientCode::GE => geth::parse_geth_engine_error_hint(error),
        _ => {
            error!("Unsupported fallback execution client: {}", client.client_name());
            Err(BuilderError::UnsupportedEngineClient(client))
        }
    }
}
