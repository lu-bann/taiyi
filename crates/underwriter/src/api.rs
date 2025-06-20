use alloy_primitives::{Address, Signature, B256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_beacon::events::HeadEvent;
use alloy_signer::k256::ecdsa::SigningKey;
use alloy_signer_local::PrivateKeySigner;
use axum::{
    extract::State,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use futures::StreamExt;
use reqwest::{header::HeaderMap, StatusCode};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use taiyi_contracts::TaiyiCoreInstance;
use taiyi_primitives::{
    bls::SecretKey, encode_util::hex_decode, BlockspaceAllocation, PreconfFeeResponse,
    PreconfRequestTypeB, SlotInfo, SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{error, info};
use url::Url;
use uuid::Uuid;

use crate::{
    block_info::{BlockInfo, BlockInfoError},
    bls_signer::BlsSigner,
    broadcast_sender::{BroadcastSender, Sender},
    constraints_stream::{get_next_slot_start, get_slot_stream, submit_constraints},
    event_stream::{get_event_stream, process_event_stream},
    preconf_fee_provider::{PreconfFeeProvider, TaiyiPreconfFeeProvider},
    slot_model::SlotModel,
    tx_cache::{TxCacheError, TxCachePerSlot},
    underwriter::{Underwriter, UnderwriterError},
};

pub const HOLESKY_GENESIS_TIMESTAMP: u64 = 1_695_902_400;

const HEALTH: &str = "/health";
const AVAILABLE_SLOTS: &str = "/commitments/v0/slots";
const PRECONF_FEE: &str = "/commitments/v0/preconf_fee";
const RESERVE_BLOCKSPACE: &str = "/commitments/v0/reserve_blockspace";
const RESERVE_SLOT_WITH_CALLDATA: &str = "/commitments/v0/submit_tx_type_a";
const RESERVE_SLOT_WITHOUT_CALLDATA: &str = "/commitments/v0/submit_tx_type_b";
const COMMITMENT_STREAM: &str = "/commitments/v0/commitment_stream";

#[derive(Debug, Error)]
pub enum PreconfApiError {
    #[error("Missing header for {key}")]
    MissingHeader { key: String },

    #[error("Slot needs to be in the future. (slot={slot}, current={current})")]
    SlotNotInFuture { slot: u64, current: u64 },

    #[error("Slot not available. (slot={slot})")]
    SlotNotAvailable { slot: u64 },

    #[error("Id not found. (id={id})")]
    UnknownId { id: Uuid },

    #[error("No preconfirmation transactions.")]
    MissingTransactions,

    #[error("{0}")]
    Signature(#[from] alloy_primitives::SignatureError),

    #[error("{0}")]
    ToStr(#[from] reqwest::header::ToStrError),

    #[error("{0}")]
    IO(#[from] std::io::Error),

    #[error("{0}")]
    BlockInfo(#[from] BlockInfoError),

    #[error("{0}")]
    Underwriter(#[from] UnderwriterError),

    #[error("{0}")]
    TxCache(#[from] TxCacheError),

    #[error("{0}")]
    Parse(#[from] url::ParseError),

    #[error("{0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("{0}")]
    FromHex(#[from] hex::FromHexError),

    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Broadcast(#[from] crate::broadcast_sender::SendError),

    #[error("{msg}")]
    Blst { msg: String },

    #[error("{0}")]
    RpcTransportError(#[from] alloy_transport::TransportError),

    #[error("{0}")]
    AlloySigner(#[from] alloy_signer::k256::ecdsa::Error),
}

impl IntoResponse for PreconfApiError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
    }
}

pub type PreconfApiResult<T> = Result<T, PreconfApiError>;

pub async fn health_check() -> impl IntoResponse {
    Json(json!({"status": "OK"}))
}

#[derive(Debug)]
pub struct PreconfState<P: PreconfFeeProvider> {
    pub underwriter: RwLock<Underwriter>,
    pub current_slot: Arc<AtomicU64>,
    pub available_slots: Arc<RwLock<Vec<u64>>>,
    pub preconf_fee_provider: Arc<RwLock<P>>,
    pub tx_cache: TxCachePerSlot,
    pub id_to_slot: Arc<RwLock<HashMap<Uuid, u64>>>,
    pub broadcast_sender: BroadcastSender,
}

impl<P: PreconfFeeProvider> PreconfState<P> {
    pub fn new(
        underwriter: Underwriter,
        current_slot: Arc<AtomicU64>,
        available_slots: Arc<RwLock<Vec<u64>>>,
        preconf_fee_provider: Arc<RwLock<P>>,
        tx_cache: TxCachePerSlot,
        broadcast_sender: BroadcastSender,
    ) -> Self {
        Self {
            underwriter: underwriter.into(),
            current_slot,
            available_slots,
            preconf_fee_provider,
            tx_cache,
            id_to_slot: Arc::new(RwLock::new(HashMap::new())),
            broadcast_sender,
        }
    }

    pub fn get_current_slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    pub fn assert_slot_in_future(&self, slot: u64) -> PreconfApiResult<()> {
        let current = self.get_current_slot();
        if slot <= current {
            return Err(PreconfApiError::SlotNotInFuture { slot, current });
        }
        Ok(())
    }

    pub async fn assert_slot_available(&self, slot: u64) -> PreconfApiResult<()> {
        if !self.available_slots.read().await.contains(&slot) {
            return Err(PreconfApiError::SlotNotAvailable { slot });
        }
        Ok(())
    }
}

fn assert_preconfirmation_transactions_available(
    request: &SubmitTypeATransactionRequest,
) -> PreconfApiResult<()> {
    if request.preconf_transaction.is_empty() {
        return Err(PreconfApiError::MissingTransactions);
    }
    Ok(())
}

impl From<blst::BLST_ERROR> for PreconfApiError {
    fn from(err: blst::BLST_ERROR) -> Self {
        Self::Blst { msg: format!("{:?}", err) }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    taiyi_rpc_addr: IpAddr,
    taiyi_rpc_port: u16,
    execution_rpc_url: String,
    beacon_rpc_url: String,
    taiyi_service_url: String,
    bls_sk: String,
    ecdsa_sk: String,
    relay_url: String,
    taiyi_core_address: Address,
    fork_version: [u8; 4],
) -> PreconfApiResult<()> {
    println!("run...");

    let genesis_timestamp = HOLESKY_GENESIS_TIMESTAMP;
    let slot_duration = Duration::from_secs(12);
    let slots_per_epoch = 32u64;
    let taiyi_addr = SocketAddr::new(taiyi_rpc_addr, taiyi_rpc_port);
    let beacon_provider = ProviderBuilder::new().connect_http(Url::from_str(&beacon_rpc_url)?);
    let execution_provider =
        ProviderBuilder::new().connect_http(Url::from_str(&execution_rpc_url)?);
    let signer =
        PrivateKeySigner::from_signing_key(SigningKey::from_slice(&hex_decode(&ecdsa_sk)?)?);

    let gas_limit = 30_000_000;
    let blob_limit = 9;
    let constraint_limit = 12;
    let chain_id = beacon_provider.get_chain_id().await?;
    let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
    let underwriter = Underwriter::new(reference_block_info);

    let current_slot = Arc::new(AtomicU64::new(0u64));
    let available_slots = Arc::new(RwLock::<Vec<u64>>::new(vec![]));
    let preconf_fee_provider =
        Arc::new(RwLock::new(TaiyiPreconfFeeProvider::new(taiyi_service_url)));
    let tx_cache = TxCachePerSlot::new();
    let broadcast_sender = BroadcastSender::new(signer.clone(), chain_id, current_slot.clone());
    let state = Arc::new(PreconfState::new(
        underwriter,
        current_slot.clone(),
        available_slots,
        preconf_fee_provider,
        tx_cache.clone(),
        broadcast_sender,
    ));
    let app = Router::new()
        .route(HEALTH, get(health_check))
        .route(RESERVE_BLOCKSPACE, post(reserve_blockspace))
        .route(RESERVE_SLOT_WITH_CALLDATA, post(reserve_slot_with_calldata))
        .route(RESERVE_SLOT_WITHOUT_CALLDATA, post(reserve_slot_without_calldata))
        .route(AVAILABLE_SLOTS, get(get_available_slots))
        .route(PRECONF_FEE, post(get_preconf_fee))
        .route(COMMITMENT_STREAM, get(commitments_stream))
        .with_state(state);

    println!("Starting rpc server...");

    let taiyi_core = TaiyiCoreInstance::new(taiyi_core_address, execution_provider.clone());
    let now_since_epoch =
        SystemTime::now().duration_since(UNIX_EPOCH).expect("Invalid time before epoch");
    let genesis_since_epoch = Duration::from_secs(genesis_timestamp);
    let now_since_genesis = now_since_epoch - genesis_since_epoch;
    let start = get_next_slot_start(&now_since_genesis, &slot_duration)?;
    let epoch_duration = Duration::from_secs(slot_duration.as_secs() * slots_per_epoch);
    let slot_model = SlotModel::new(genesis_timestamp, slot_duration, epoch_duration);
    let slot = slot_model.get_slot(now_since_epoch.as_secs());
    let next_slot_count = slot.epoch * slots_per_epoch + slot.slot + 1;
    let slot_stream = get_slot_stream(start, next_slot_count, slot_duration)?;

    let store_current_slot = |head_event: HeadEvent| {
        println!("update current slot {:?}", head_event);
        current_slot.store(head_event.slot, Ordering::Relaxed);
    };

    let event_stream = get_event_stream(&beacon_rpc_url).await?;
    let listener = TcpListener::bind(&taiyi_addr).await?;

    let bls_private_key =
        SecretKey::from_bytes(&hex_decode(&bls_sk).map_err(PreconfApiError::from)?)?;
    let bls_signer =
        BlsSigner::new(signer.address(), Some(chain_id), bls_private_key, fork_version);

    tokio::select!(
        _ = axum::serve(listener, app) => { println!("terminating server") },
        _ = process_event_stream(event_stream, store_current_slot) => { println!("terminating event stream")},
        _ = submit_constraints(taiyi_core, slot_stream, execution_provider, tx_cache.clone(), signer, bls_signer, relay_url) => { println!("terminating constraint stream")}
    );
    Ok(())
}

fn get_signer_and_signature(
    headers: HeaderMap,
    hash: B256,
) -> PreconfApiResult<(Address, Signature)> {
    let signature = {
        let auth = headers
            .get("x-luban-signature")
            .ok_or(PreconfApiError::MissingHeader { key: "x-luban-signature".to_string() })?;

        let sig = auth.to_str()?;
        Signature::from_str(sig)?
    };

    let signer = signature.recover_address_from_prehash(&hash)?;
    Ok((signer, signature))
}

async fn reserve_blockspace<P: PreconfFeeProvider>(
    headers: HeaderMap,
    State(state): State<Arc<PreconfState<P>>>,
    Json(request): Json<BlockspaceAllocation>,
) -> PreconfApiResult<Json<Uuid>> {
    let chain_id = 123u64;
    let (signer, signature) = get_signer_and_signature(headers, request.hash(chain_id))?;
    info!("Received blockspace reservation request, signer: {}", signer);

    let target_slot = request.target_slot;
    state.assert_slot_in_future(target_slot)?;
    state.assert_slot_available(target_slot).await?;

    state.underwriter.write().await.reserve_blockspace(
        target_slot,
        request.gas_limit,
        request.blob_count,
    )?;
    let id = Uuid::new_v4();
    let preconf_request = PreconfRequestTypeB {
        allocation: request,
        alloc_sig: signature,
        transaction: None,
        signer,
    };
    state.id_to_slot.write().await.insert(id, target_slot);
    let mut tx_cache = state.tx_cache.clone();
    tx_cache.add_without_calldata(target_slot, id, preconf_request).await;
    Ok(Json(id))
}

async fn reserve_slot_with_calldata<P: PreconfFeeProvider>(
    headers: HeaderMap,
    State(state): State<Arc<PreconfState<P>>>,
    Json(request): Json<SubmitTypeATransactionRequest>,
) -> PreconfApiResult<Json<Uuid>> {
    let (signer, _) = get_signer_and_signature(headers, request.digest())?;
    info!("Received slot reservation request with calldata, signer: {}", signer);

    assert_preconfirmation_transactions_available(&request)?;

    let id = Uuid::new_v4();

    let preconf_fee = state.preconf_fee_provider.read().await.get(request.target_slot).await?;
    state
        .underwriter
        .write()
        .await
        .reserve_slot_with_calldata(
            id,
            request,
            preconf_fee,
            state.broadcast_sender.clone(),
            signer,
        )
        .await?;
    Ok(Json(id))
}

async fn reserve_slot_without_calldata<P: PreconfFeeProvider>(
    headers: HeaderMap,
    State(state): State<Arc<PreconfState<P>>>,
    Json(request): Json<SubmitTransactionRequest>,
) -> PreconfApiResult<Json<()>> {
    let _ = get_signer_and_signature(headers, request.digest())?;
    info!("Received slot reservation request without calldata");

    let slot = state
        .id_to_slot
        .write()
        .await
        .remove(&request.request_id)
        .ok_or(PreconfApiError::UnknownId { id: request.request_id })?;
    let mut tx_cache = state.tx_cache.clone();
    let preconf_request =
        tx_cache.add_calldata(slot, request.request_id, request.transaction).await?;

    state.broadcast_sender.sign_and_send(request.request_id, preconf_request).await?;
    Ok(Json(()))
}

pub async fn get_available_slots<P: PreconfFeeProvider>(
    State(state): State<Arc<PreconfState<P>>>,
) -> PreconfApiResult<Json<Vec<SlotInfo>>> {
    let slots = state.available_slots.read().await;
    let mut underwriter = state.underwriter.write().await;
    let slot_infos = slots
        .iter()
        .map(|slot| {
            let block_info = underwriter.get_block_info(*slot).0;
            SlotInfo {
                slot: *slot,
                gas_available: block_info.remaining_gas,
                blobs_available: block_info.remaining_blobs,
                constraints_available: block_info.remaining_constraints,
            }
        })
        .collect();
    Ok(Json(slot_infos))
}

pub async fn get_preconf_fee<P: PreconfFeeProvider>(
    State(state): State<Arc<PreconfState<P>>>,
    Json(slot): Json<u64>,
) -> PreconfApiResult<Json<PreconfFeeResponse>> {
    Ok(Json(state.preconf_fee_provider.read().await.get(slot).await?))
}

async fn commitments_stream<P: PreconfFeeProvider>(
    State(state): State<Arc<PreconfState<P>>>,
) -> axum::response::Sse<impl futures::Stream<Item = eyre::Result<axum::response::sse::Event>>> {
    let stream = tokio_stream::wrappers::BroadcastStream::new(state.broadcast_sender.subscribe());
    let filtered = stream.map(|result| {
        Ok(axum::response::sse::Event::default()
            .data(serde_json::to_string(&vec![result?])?)
            .event("commitment_data")
            .retry(std::time::Duration::from_millis(50)))
    });

    axum::response::Sse::new(filtered).keep_alive(axum::response::sse::KeepAlive::default())
}
