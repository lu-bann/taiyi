use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{Bloom, B256};
use alloy_rpc_types_engine::{Claims, ExecutionPayload, JwtSecret};
use eyre::Result;
use hex::FromHex;
use regex::Regex;
use reqwest::{header, header::HeaderMap, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::trace;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineErrorPayload {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct EngineClient {
    client: reqwest::Client,
    jwt_secret: JwtSecret,
    engine_api: Url,
}

impl EngineClient {
    pub fn new(engine_api: Url, jwt_secret: JwtSecret) -> Self {
        let client = reqwest::Client::builder()
            .default_headers(HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            )]))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Build reqwest client failed");

        Self { client, jwt_secret, engine_api }
    }

    // The jwt token is valid for 60 seconds
    pub fn generate_claims(&self, time: Option<SystemTime>) -> Claims {
        let now = time.unwrap_or(SystemTime::now());
        let iat = now.duration_since(UNIX_EPOCH).expect("invalid time").as_secs();
        let exp = Some(iat + 60);
        Claims { iat, exp }
    }

    pub async fn fetch_next_payload_hint(
        &self,
        exec_payload: &ExecutionPayload,
        versioned_hashes: &[B256],
        parent_beacon_root: B256,
    ) -> Result<EngineApiHint> {
        let claims = self.generate_claims(None);
        let jwt_header = self.jwt_secret.encode(&claims).expect("Encode jwt failed");
        let jwt_header = format!("Bearer {jwt_header}");

        let body = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"engine_newPayloadV3","params":[{}, {}, "{:?}"]}}"#,
            serde_json::to_string(&exec_payload)?,
            serde_json::to_string(&versioned_hashes)?,
            parent_beacon_root
        );

        let raw_hint = self
            .client
            .post(self.engine_api.clone())
            .header("Content-Type", "application/json")
            .header(header::AUTHORIZATION, &jwt_header)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        let Some(hint_value) = parse_geth_response(&raw_hint) else {
            // If the hint is not found, it means that we likely got a VALID
            // payload response or an error message that we can't parse.
            if raw_hint.contains("\"status\":\"VALID\"") {
                return Ok(EngineApiHint::ValidPayload);
            }
            return Err(eyre::eyre!("failed to parse hint: {}", raw_hint));
        };

        trace!("engine hint: {:?}", raw_hint);

        // Match the hint value to the corresponding header field and return it
        if raw_hint.contains("blockhash mismatch") {
            return Ok(EngineApiHint::BlockHash(B256::from_hex(hint_value)?));
        } else if raw_hint.contains("invalid gas used") {
            return Ok(EngineApiHint::GasUsed(hint_value.parse()?));
        } else if raw_hint.contains("invalid merkle root") {
            return Ok(EngineApiHint::StateRoot(B256::from_hex(hint_value)?));
        } else if raw_hint.contains("invalid receipt root hash") {
            return Ok(EngineApiHint::ReceiptsRoot(B256::from_hex(hint_value)?));
        } else if raw_hint.contains("invalid bloom") {
            return Ok(EngineApiHint::LogsBloom(Bloom::from_hex(&hint_value)?));
        };

        Err(eyre::eyre!("Unexpected: failed to parse any hint from engine response".to_string(),))
    }
}

/// Engine API hint values that can be fetched from the engine API
/// to complete the sealed block. These hints are used to fill in
/// missing values in the block header.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum EngineApiHint {
    BlockHash(B256),
    GasUsed(u64),
    StateRoot(B256),
    ReceiptsRoot(B256),
    LogsBloom(Bloom),
    ValidPayload,
}

/// Parse the hint value from the engine response.
/// An example error message from the engine API looks like this:
/// ```text
/// {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"local: blockhash mismatch: got 0x... expected 0x..."}}
/// ```
///
/// Geth Reference:
/// - [ValidateState](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/core/block_validator.go#L122-L151>)
/// - [Blockhash Mismatch](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/beacon/engine/types.go#L253-L256>)
pub(crate) fn parse_geth_response(error: &str) -> Option<String> {
    // Capture either the "local" or "got" value from the error message
    let re = Regex::new(r"(?:local:|got) ([0-9a-zA-Z]+)").expect("valid regex");

    re.captures(error)
        .and_then(|capture| capture.get(1).map(|matched| matched.as_str().to_string()))
}
