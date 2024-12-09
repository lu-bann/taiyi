use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{utils::format_ether, B256, U256};
use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
    routing::get,
    Router,
};
use cb_common::{
    config::PbsConfig,
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        error::{PbsError, ValidationError},
        GetHeaderParams, GetHeaderResponse, RelayClient, SignedBlindedBeaconBlock,
        SignedExecutionPayloadHeader, SubmitBlindedBlockResponse, Version, EMPTY_TX_ROOT_HASH,
        HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS,
    },
    signature::verify_signed_message,
    types::Chain,
    utils::{get_user_agent_with_version, ms_into_slot},
};
use cb_pbs::{get_header, register_validator, submit_block, TIMEOUT_ERROR_CODE};
use commit_boost::prelude::*;
use ethereum_consensus::deneb::Context;
use eyre::Result;
use futures::future::join_all;
use parking_lot::Mutex;
use reqwest::{header::USER_AGENT, StatusCode};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::{
    block_builder::{LocalBlockBuilder, SignedPayloadResponse},
    constraints::ConstraintsCache,
    error::PbsClientError,
    proofs::verify_multiproofs,
    types::{
        ExtraConfig, GetHeaderWithProofsResponse, RequestConfig, SignedConstraints,
        SignedExecutionPayloadHeaderWithProofs, BUILDER_CONSTRAINTS_PATH,
    },
};

const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";

#[allow(unused)]
#[derive(Clone)]
pub struct SidecarBuilderState {
    config: ExtraConfig,
    constraints: ConstraintsCache,
    local_block_builder: LocalBlockBuilder,
    local_payload: Arc<Mutex<Option<SignedPayloadResponse>>>,
}

impl BuilderApiState for SidecarBuilderState {}

impl SidecarBuilderState {
    pub async fn new(extra: &ExtraConfig) -> Self {
        let context: Context =
            extra.network.clone().try_into().expect("failed to convert network to context");

        let local_block_builder = LocalBlockBuilder::new(
            context,
            extra.beacon_api.clone(),
            extra.engine_api.clone(),
            extra.execution_api.clone(),
            extra.engine_jwt.0,
            extra.fee_recipient,
            extra.builder_private_key.clone().0,
        )
        .await;
        Self {
            config: extra.clone(),
            constraints: ConstraintsCache::new(),
            local_block_builder,
            local_payload: Arc::new(Mutex::new(None)),
        }
    }
}

pub struct SidecarBuilderApi;

#[async_trait]
impl BuilderApi<SidecarBuilderState> for SidecarBuilderApi {
    async fn register_validator(
        registrations: Vec<ValidatorRegistration>,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<()> {
        let (slot, _) = state.get_slot_and_uuid();
        state.data.constraints.prune(slot);

        register_validator(registrations, req_headers, state).await
    }

    async fn get_header(
        params: GetHeaderParams,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<Option<GetHeaderResponse>> {
        match get_header(params, req_headers, state.clone()).await {
            Ok(Some(response)) => {
                let mut local_payload = state.data.local_payload.lock();
                *local_payload = None;
                return Ok(Some(response));
            }
            Err(err) => {
                warn!("get header from relay failed, slot: {}, error: {}", params.slot, err);
            }
            _ => {
                warn!("get header from relay failed, slot: {}", params.slot);
            }
        }

        // get builder constraints from one of the relays
        for relay in state.relays() {
            let builder_constraints_url = relay
                .builder_api_url(BUILDER_CONSTRAINTS_PATH)
                .expect("failed to build builder_constraints url");
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Build reqwest client failed");
            match client
                .post(builder_constraints_url.clone())
                .query(&[("slot", params.slot.to_string())])
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.json::<Vec<SignedConstraints>>().await {
                            Ok(constraints) => {
                                if constraints.is_empty() {
                                    warn!(
                                        "constraints is empty, url: {}, slot: {}",
                                        builder_constraints_url.to_string(),
                                        params.slot
                                    );
                                    continue;
                                }
                                if let Err(err) =
                                    state.data.constraints.insert(constraints[0].message.clone())
                                {
                                    warn!(
                                        "failed to insert constraints, slot: {}, error: {}",
                                        params.slot, err
                                    );
                                    continue;
                                }
                            }
                            Err(err) => {
                                warn!("failed to parse constraints from response, url: {}, slot: {}, error: {}", builder_constraints_url.to_string(), params.slot, err);
                                continue;
                            }
                        }
                        break;
                    }
                }
                Err(err) => {
                    warn!(
                        "get constraints from relay failed, url: {}, slot: {}, error: {}",
                        builder_constraints_url.to_string(),
                        params.slot,
                        err
                    );
                }
            }
        }
        // todo: error handling
        let transactions = state.data.constraints.get(params.slot).expect("constraints not found");
        let resp = state
            .data
            .local_block_builder
            .build_signed_payload_response(params.slot, &transactions.transactions)
            .await?;
        {
            let mut local_payload = state.data.local_payload.lock();
            *local_payload = Some(resp.clone());
        }
        Ok(Some(GetHeaderResponse { version: Version::Deneb, data: resp.header.clone() }))
    }

    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<SubmitBlindedBlockResponse> {
        if let Some(local_payload) = state.data.local_payload.lock().take() {
            // todo: do some checks
            return Ok(SubmitBlindedBlockResponse {
                version: Version::Deneb,
                data: local_payload.payload.clone(),
            });
        }
        submit_block(signed_blinded_block, req_headers, state).await
    }

    fn extra_routes() -> Option<Router<PbsState<SidecarBuilderState>>> {
        let mut router = Router::new();
        router = router.route(GET_HEADER_WITH_PROOFS_PATH, get(get_header_with_proofs));
        Some(router)
    }
}

/// Get a header with proofs for a given slot and parent hash.
/// The code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/v0.3.0-alpha/bolt-boost/src/server.rs#L170
async fn get_header_with_proofs(
    State(state): State<PbsState<SidecarBuilderState>>,
    Path(params): Path<GetHeaderParams>,
    req_headers: HeaderMap,
) -> Result<impl IntoResponse, PbsClientError> {
    let slot_uuid = state.get_or_update_slot_uuid(params.slot);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    info!(parent_hash=%params.parent_hash, validator_pubkey=%params.pubkey, ms_into_slot);

    let max_timeout_ms = state
        .pbs_config()
        .timeout_get_header_ms
        .min(state.pbs_config().late_in_slot_time_ms.saturating_sub(ms_into_slot));

    if max_timeout_ms == 0 {
        warn!(
            ms_into_slot,
            threshold = state.pbs_config().late_in_slot_time_ms,
            "late in slot, skipping relay requests"
        );

        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    // TODO: error handling
    send_headers.insert(
        HEADER_SLOT_UUID_KEY,
        HeaderValue::from_str(&slot_uuid.to_string())
            .expect("failed to convert slot_uuid to string"),
    );
    send_headers.insert(
        USER_AGENT,
        get_user_agent_with_version(&req_headers)
            .expect("failed to get user agent with version from request headers"),
    );

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays {
        handles.push(send_timed_get_header(
            params,
            relay.clone(),
            state.config.chain,
            state.pbs_config(),
            send_headers.clone(),
            ms_into_slot,
            max_timeout_ms,
        ));
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    let mut hash_to_proofs = HashMap::new();

    // Get and remove the constraints for this slot
    let maybe_constraints = state.data.constraints.remove(params.slot);

    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_ref();

        match res {
            Ok(Some(res)) => {
                let root = res.data.header.message.header.transactions_root;

                let start = Instant::now();

                // If we have constraints to verify, do that here in order to validate the bid
                if let Some(ref constraints) = maybe_constraints {
                    // Verify the multiproofs and continue if not valid
                    if let Err(e) = verify_multiproofs(&constraints.1, &res.data.proofs, root) {
                        error!(?e, relay_id, "Failed to verify multiproof, skipping bid");
                        continue;
                    }

                    tracing::debug!("Verified multiproof in {:?}", start.elapsed());

                    // Save the proofs per block hash
                    hash_to_proofs
                        .insert(res.data.header.message.header.block_hash, res.data.proofs);
                }

                let vanilla_response =
                    GetHeaderResponse { version: res.version, data: res.data.header };

                relay_bids.push(vanilla_response)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(?err, relay_id),
        }
    }

    if let Some(winning_bid) = state.add_bids(params.slot, relay_bids) {
        let header_with_proofs = GetHeaderWithProofsResponse {
            data: SignedExecutionPayloadHeaderWithProofs {
                // If there are no proofs, default to empty. This should never happen unless there
                // were no constraints to verify.
                proofs: hash_to_proofs
                    .get(&winning_bid.data.message.header.block_hash)
                    .cloned()
                    .unwrap_or_default(),
                header: winning_bid.data,
            },
            version: winning_bid.version,
        };

        Ok((StatusCode::OK, axum::Json(header_with_proofs)).into_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

async fn send_timed_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    pbs_config: &PbsConfig,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
) -> Result<Option<GetHeaderWithProofsResponse>, PbsError> {
    let url = relay.get_url(&format!(
        "/eth/v1/builder/header_with_proofs/{}/{}/{}",
        params.slot, params.parent_hash, params.pubkey
    ))?;

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let delay = target_ms.saturating_sub(ms_into_slot);
            if delay > 0 {
                debug!(target_ms, ms_into_slot, "TG: waiting to send first header request");
                timeout_left_ms = timeout_left_ms.saturating_sub(delay);
                sleep(Duration::from_millis(delay)).await;
            } else {
                debug!(target_ms, ms_into_slot, "TG: request already late enough in slot");
            }
        }

        if let Some(send_freq_ms) = relay.config.frequency_get_header_ms {
            let mut handles = Vec::new();

            debug!(send_freq_ms, timeout_left_ms, "TG: sending multiple header requests");

            loop {
                handles.push(tokio::spawn(send_one_get_header(
                    params,
                    relay.clone(),
                    chain,
                    pbs_config.skip_sigverify,
                    pbs_config.min_bid_wei,
                    RequestConfig {
                        timeout_ms: timeout_left_ms,
                        url: url.clone(),
                        headers: headers.clone(),
                    },
                )));

                if timeout_left_ms > send_freq_ms {
                    // enough time for one more
                    timeout_left_ms = timeout_left_ms.saturating_sub(send_freq_ms);
                    sleep(Duration::from_millis(send_freq_ms)).await;
                } else {
                    break;
                }
            }

            let results = join_all(handles).await;
            let mut n_headers = 0;

            if let Some((_, maybe_header)) = results
                .into_iter()
                .filter_map(|res| {
                    // ignore join error and timeouts, log other errors
                    res.ok().and_then(|inner_res| match inner_res {
                        Ok(maybe_header) => {
                            n_headers += 1;
                            Some(maybe_header)
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(?err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .max_by_key(|(start_time, _)| *start_time)
            {
                debug!(n_headers, "TG: received headers from relay");
                return Ok(maybe_header);
            }
            // all requests failed
            warn!("TG: no headers received");

            return Err(PbsError::RelayResponse {
                error_msg: "no headers received".to_string(),
                code: TIMEOUT_ERROR_CODE,
            });
        }
    }

    // if no timing games or no repeated send, just send one request
    send_one_get_header(
        params,
        relay,
        chain,
        pbs_config.skip_sigverify,
        pbs_config.min_bid_wei,
        RequestConfig { timeout_ms: timeout_left_ms, url, headers },
    )
    .await
    .map(|(_, maybe_header)| maybe_header)
}

async fn send_one_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    skip_sigverify: bool,
    min_bid_wei: U256,
    mut req_config: RequestConfig,
) -> Result<(u64, Option<GetHeaderWithProofsResponse>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    let start_request = Instant::now();
    let res = match relay
        .client
        .get(req_config.url)
        .timeout(Duration::from_millis(req_config.timeout_ms))
        .headers(req_config.headers)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    let code = res.status();
    let response_bytes = res.bytes().await?;
    if !code.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        });
    };

    if code == StatusCode::NO_CONTENT {
        debug!(
            ?code,
            latency = ?request_latency,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    let get_header_response: GetHeaderWithProofsResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| PbsError::JsonDecode {
            err: e,
            raw: String::from_utf8(response_bytes.to_vec()).unwrap_or("Invalid UTF-8".to_string()),
        })?;

    debug!(
        latency = ?request_latency,
        block_hash = %get_header_response.data.message.header.block_hash,
        value_eth = format_ether(get_header_response.data.message.value),
        "received new header"
    );

    validate_header(
        &get_header_response.data,
        chain,
        relay.pubkey().into(),
        params.parent_hash,
        skip_sigverify,
        min_bid_wei,
    )?;

    Ok((start_request_time, Some(get_header_response)))
}

fn validate_header(
    signed_header: &SignedExecutionPayloadHeader,
    chain: Chain,
    expected_relay_pubkey: BlsPublicKey,
    parent_hash: B256,
    skip_sig_verify: bool,
    minimum_bid_wei: U256,
) -> Result<(), ValidationError> {
    let block_hash = signed_header.message.header.block_hash;
    let received_relay_pubkey = signed_header.message.pubkey;
    let tx_root = signed_header.message.header.transactions_root;
    let value = signed_header.message.value;

    if block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if parent_hash != signed_header.message.header.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: parent_hash,
            got: signed_header.message.header.parent_hash,
        });
    }

    if tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if value <= minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: value });
    }

    if expected_relay_pubkey != received_relay_pubkey.into() {
        return Err(ValidationError::PubkeyMismatch {
            expected: expected_relay_pubkey.into(),
            got: received_relay_pubkey,
        });
    }

    if !skip_sig_verify {
        // Verify the signature against the builder domain.
        verify_signed_message(
            chain,
            &received_relay_pubkey,
            &signed_header.message,
            &signed_header.signature,
            APPLICATION_BUILDER_DOMAIN,
        )
        .map_err(ValidationError::Sigverify)?;
    }

    Ok(())
}
