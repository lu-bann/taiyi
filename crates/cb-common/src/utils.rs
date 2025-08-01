use std::{
    net::Ipv4Addr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::U256;
use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use axum::http::HeaderValue;
use blst::min_pk::{PublicKey, Signature};
use rand::prelude::*;
use reqwest::header::HeaderMap;
#[cfg(test)]
use serde::{de::DeserializeOwned, Serialize};
use ssz::{Decode, Encode};
use tracing::Level;
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{
    fmt::{format::Format, Layer},
    prelude::*,
    EnvFilter,
};

use crate::{
    config::LogsSettings,
    constants::SIGNER_JWT_EXPIRATION,
    pbs::HEADER_VERSION_VALUE,
    types::{Chain, Jwt, JwtClaims, ModuleId},
};

const MILLIS_PER_SECOND: u64 = 1_000;

pub fn timestamp_of_slot_start_sec(slot: u64, chain: Chain) -> u64 {
    chain.genesis_time_sec() + slot * chain.slot_time_sec()
}
pub fn timestamp_of_slot_start_millis(slot: u64, chain: Chain) -> u64 {
    timestamp_of_slot_start_sec(slot, chain) * MILLIS_PER_SECOND
}
pub fn ms_into_slot(slot: u64, chain: Chain) -> u64 {
    let slot_start_ms = timestamp_of_slot_start_millis(slot, chain);
    utcnow_ms().saturating_sub(slot_start_ms)
}

/// Seconds
pub fn utcnow_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time is before epoch").as_secs()
}
/// Millis
pub fn utcnow_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time is before epoch").as_millis() as u64
}
/// Micros
pub fn utcnow_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time is before epoch").as_micros() as u64
}
/// Nanos
pub fn utcnow_ns() -> u64 {
    // safe until ~2554
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time is before epoch").as_nanos() as u64
}

pub const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;
pub fn eth_to_wei(eth: f64) -> U256 {
    U256::from((eth * WEI_PER_ETH as f64).floor())
}

// Serde
/// Test that the encoding and decoding works, returns the decoded struct
#[cfg(test)]
pub fn test_encode_decode<T: Serialize + DeserializeOwned>(d: &str) -> T {
    use serde_json::Value;

    let decoded = serde_json::from_str::<T>(d).expect("deserialize");

    // re-encode to make sure that different formats are ignored
    let encoded = serde_json::to_string(&decoded).unwrap();
    let original_v: Value = serde_json::from_str(d).unwrap();
    let encoded_v: Value = serde_json::from_str(&encoded).unwrap();

    if original_v != encoded_v {
        println!("ORIGINAL: {original_v}");
        println!("ENCODED: {encoded_v}");
        panic!("encode mismatch");
    }

    decoded
}

pub fn test_encode_decode_ssz<T: Encode + Decode>(d: &[u8]) -> T {
    let decoded = T::from_ssz_bytes(d).expect("deserialize");
    let encoded = T::as_ssz_bytes(&decoded);

    assert_eq!(encoded, d);

    decoded
}

pub mod as_eth_str {
    use alloy::primitives::{
        utils::{format_ether, parse_ether},
        U256,
    };
    use serde::Deserialize;

    use super::eth_to_wei;

    pub fn serialize<S>(data: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format_ether(*data);
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrF64 {
            Str(String),
            F64(f64),
        }

        let value = StringOrF64::deserialize(deserializer)?;
        let wei = match value {
            StringOrF64::Str(s) => {
                parse_ether(&s).map_err(|_| serde::de::Error::custom("invalid eth amount"))?
            }
            StringOrF64::F64(f) => eth_to_wei(f),
        };

        Ok(wei)
    }
}

pub const fn default_u64<const U: u64>() -> u64 {
    U
}

pub const fn default_u32<const U: u32>() -> u32 {
    U
}

pub const fn default_u16<const U: u16>() -> u16 {
    U
}

pub const fn default_bool<const U: bool>() -> bool {
    U
}

pub const fn default_host() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

pub const fn default_u256() -> U256 {
    U256::ZERO
}

// LOGGING
pub fn initialize_tracing_log(
    module_id: &str,
    settings: LogsSettings,
) -> eyre::Result<(Option<WorkerGuard>, Option<WorkerGuard>)> {
    let format = Format::default().with_target(false).compact();

    let mut stdout_guard = None;
    let mut file_guard = None;
    let mut layers = Vec::new();

    if settings.stdout.enabled {
        let config = settings.stdout;

        let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
        stdout_guard = Some(guard);

        let filter = format_crates_filter(Level::INFO.as_str(), config.level.as_str());
        let format = format.clone().with_ansi(config.color);

        let layer =
            Layer::default().event_format(format).with_writer(writer).with_filter(filter).boxed();

        layers.push(layer);
    };

    if settings.file.enabled {
        let config = settings.file;

        let mut builder =
            tracing_appender::rolling::Builder::new().filename_prefix(module_id.to_lowercase());
        if let Some(value) = config.max_files {
            builder = builder.max_log_files(value);
        }
        let file_appender = builder
            .rotation(Rotation::DAILY)
            .build(config.dir_path)
            .expect("failed building rolling file appender");
        let (writer, guard) = tracing_appender::non_blocking(file_appender);
        file_guard = Some(guard);

        let filter = format_crates_filter(Level::INFO.as_str(), config.level.as_str());
        let format = format.clone().with_ansi(false);
        let layer =
            Layer::default().event_format(format).with_writer(writer).with_filter(filter).boxed();

        layers.push(layer);
    };

    tracing_subscriber::registry().with(layers).init();

    Ok((stdout_guard, file_guard))
}

// all commit boost crates
// TODO: this can probably done without unwrap
fn format_crates_filter(default_level: &str, crates_level: &str) -> EnvFilter {
    let s = format!(
        "{default_level},cb_signer={crates_level},cb_pbs={crates_level},cb_common={crates_level},cb_metrics={crates_level}",
    );
    s.parse().expect("Provide an error instead")
}

pub fn print_logo() {
    println!(
        r#"   ______                          _ __     ____                   __
  / ____/___  ____ ___  ____ ___  (_) /_   / __ )____  ____  _____/ /_
 / /   / __ \/ __ `__ \/ __ `__ \/ / __/  / __  / __ \/ __ \/ ___/ __/
/ /___/ /_/ / / / / / / / / / / / / /_   / /_/ / /_/ / /_/ (__  ) /_
\____/\____/_/ /_/ /_/_/ /_/ /_/_/\__/  /_____/\____/\____/____/\__/
                                                                      "#
    )
}

// Crypto conversions

pub fn alloy_pubkey_to_blst(pubkey: &BlsPublicKey) -> Result<PublicKey, blst::BLST_ERROR> {
    PublicKey::key_validate(pubkey.as_slice())
}

pub fn alloy_sig_to_blst(signature: &BlsSignature) -> Result<Signature, blst::BLST_ERROR> {
    Signature::from_bytes(signature.as_slice())
}

pub fn blst_pubkey_to_alloy(pubkey: &PublicKey) -> BlsPublicKey {
    BlsPublicKey::from_slice(&pubkey.to_bytes())
}

/// Create a JWT for the given module id with expiration
pub fn create_jwt(module_id: &ModuleId, secret: &str) -> eyre::Result<Jwt> {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &JwtClaims {
            module: module_id.to_string(),
            exp: jsonwebtoken::get_current_timestamp() + SIGNER_JWT_EXPIRATION,
        },
        &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(Into::into)
    .map(Jwt::from)
}

/// Decode a JWT and return the module id. IMPORTANT: This function does not
/// validate the JWT, it only obtains the module id from the claims.
pub fn decode_jwt(jwt: Jwt) -> eyre::Result<ModuleId> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();

    let module = jsonwebtoken::decode::<JwtClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(&[]),
        &validation,
    )?
    .claims
    .module
    .into();

    Ok(module)
}

/// Validate a JWT with the given secret
pub fn validate_jwt(jwt: Jwt, secret: &str) -> eyre::Result<()> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.leeway = 10;

    jsonwebtoken::decode::<JwtClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )
    .map(|_| ())
    .map_err(From::from)
}

/// Generates a random string
pub fn random_jwt_secret() -> String {
    rand::rng().sample_iter(&rand::distr::Alphanumeric).take(32).map(char::from).collect()
}

/// Returns the user agent from the request headers or an empty string if not
/// present
pub fn get_user_agent(req_headers: &HeaderMap) -> String {
    req_headers
        .get(reqwest::header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Adds the commit boost version to the existing user agent
pub fn get_user_agent_with_version(req_headers: &HeaderMap) -> eyre::Result<HeaderValue> {
    let ua = get_user_agent(req_headers);
    Ok(HeaderValue::from_str(&format!("commit-boost/{HEADER_VERSION_VALUE} {}", ua))?)
}

#[cfg(unix)]
pub async fn wait_for_signal() -> eyre::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }

    Ok(())
}

#[cfg(windows)]
pub async fn wait_for_signal() -> eyre::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{create_jwt, decode_jwt, validate_jwt};
    use crate::types::{Jwt, ModuleId};

    #[test]
    fn test_jwt_validation() {
        // Check valid JWT
        let jwt = create_jwt(&ModuleId("DA_COMMIT".to_string()), "secret").unwrap();
        let module_id = decode_jwt(jwt.clone()).unwrap();
        assert_eq!(module_id, ModuleId("DA_COMMIT".to_string()));
        let response = validate_jwt(jwt, "secret".as_ref());
        assert!(response.is_ok());

        // Check expired JWT
        let expired_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NDI5OTU5NDYsIm1vZHVsZSI6IkRBX0NPTU1JVCJ9.iiq4Z2ed2hk3c3c-cn2QOQJWE5XUOc5BoaIPT-I8q-s".to_string());
        let response = validate_jwt(expired_jwt, "secret");
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "ExpiredSignature");

        // Check invalid signature JWT
        let invalid_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NDI5OTU5NDYsIm1vZHVsZSI6IkRBX0NPTU1JVCJ9.w9WYdDNzgDjYTvjBkk4GGzywGNBYPxnzU2uJWzPUT1s".to_string());
        let response = validate_jwt(invalid_jwt, "secret");
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "InvalidSignature");
    }
}
