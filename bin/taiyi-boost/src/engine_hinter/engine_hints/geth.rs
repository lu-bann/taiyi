// the code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/builder/fallback/engine_hints/geth.rs
use alloy::primitives::{Bloom, B256};
use lazy_static::lazy_static;
use regex::Regex;
use taiyi_primitives::encode_util::hex_decode;

use crate::{engine_hinter::EngineApiHint, error::BuilderError};

lazy_static! {
    /// Capture either the "local" or "got" value from the error message
    static ref REGEX: Regex = Regex::new(r"(?:local:|got) ([0-9a-zA-Z]+)").expect("valid regex");
}

/// Parse a hinted value from the engine response.
/// An example error message from the engine API looks like this:
///
/// ```json
/// {
///     "jsonrpc": "2.0",
///     "id": 1,
///     "error": {
///         "code":-32000,
///          "message": "local: blockhash mismatch: got 0x... expected 0x..."
///     }
/// }
/// ```
///
/// Geth Reference:
/// - [ValidateState](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/core/block_validator.go#L122-L151>)
/// - [Blockhash Mismatch](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/beacon/engine/types.go#L253-L256>)
pub fn parse_geth_engine_error_hint(error: &str) -> Result<Option<EngineApiHint>, BuilderError> {
    let raw_hint_value = match REGEX.captures(error).and_then(|cap| cap.get(1)) {
        Some(matched) => matched.as_str().to_string(),
        None => return Ok(None),
    };

    // Match the hint value to the corresponding hint type based on other parts of the error message
    if error.contains("blockhash mismatch") {
        return Ok(Some(EngineApiHint::BlockHash(B256::from_slice(&hex_decode(&raw_hint_value)?))));
    } else if error.contains("invalid gas used") {
        return Ok(Some(EngineApiHint::GasUsed(raw_hint_value.parse()?)));
    } else if error.contains("invalid merkle root") {
        return Ok(Some(EngineApiHint::StateRoot(B256::from_slice(&hex_decode(&raw_hint_value)?))));
    } else if error.contains("invalid receipt root hash") {
        return Ok(Some(EngineApiHint::ReceiptsRoot(B256::from_slice(&hex_decode(
            &raw_hint_value,
        )?))));
    } else if error.contains("invalid bloom") {
        return Ok(Some(EngineApiHint::LogsBloom(Bloom::from_slice(&hex_decode(
            &raw_hint_value,
        )?))));
    };

    // Match some error message that we don't know how to handle
    if error.contains("could not apply tx") {
        return Err(BuilderError::InvalidTransactions(error.to_string()));
    }

    Err(BuilderError::UnsupportedEngineHint(error.to_string()))
}
