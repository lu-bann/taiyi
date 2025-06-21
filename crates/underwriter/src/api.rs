use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip4844::env_settings::EnvKzgSettings;
use alloy_primitives::{Address, Signature, B256};
use alloy_provider::{Provider, ProviderBuilder};
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
use taiyi_contracts::{TaiyiCoreInstance, TaiyiEscrowInstance};
use taiyi_primitives::{
    bls::{bls_pubkey_to_alloy, SecretKey},
    encode_util::hex_decode,
    slot_info::{HoleskySlotInfoFactory, SlotInfo},
    BlockspaceAllocation, PreconfFee, PreconfRequest, PreconfRequestTypeB,
    SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{error, info};
use url::Url;
use uuid::Uuid;

use crate::{
    account_info::OnChainAccountInfoProvider,
    account_state::AccountState,
    bls_signer::BlsSigner,
    broadcast_sender::{BroadcastSender, Sender},
    constraints_stream::{get_next_slot_start, get_slot_stream, submit_constraints},
    event_stream::{
        get_event_stream, process_event_stream, Noop, StoreAvailableSlotsDecorator,
        StoreLastSlotDecorator, StreamError,
    },
    preconf_fee_provider::{PreconfFeeProvider, TaiyiPreconfFeeProvider},
    slot_model::SlotModel,
    tx_cache::{TxCacheError, TxCachePerSlot},
    underwriter::{verify_tip, Underwriter, UnderwriterError},
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

    #[error("Slot needs to be in the future. (slot={slot}, last slot={last})")]
    SlotNotInFuture { slot: u64, last: u64 },

    #[error("Slot not available. (slot={slot})")]
    SlotNotAvailable { slot: u64 },

    #[error("Id not found. (id={id})")]
    UnknownId { id: Uuid },

    #[error("No preconfirmation transactions.")]
    MissingTransactions,

    #[error("Invalid preconf fee (expected={expected:?}, fee={fee:?}")]
    InvalidPreconfFee { fee: PreconfFee, expected: PreconfFee },

    #[error("Received request after deadline expired (deadline={deadline}, received={received})")]
    DeadlineExpired { deadline: u64, received: u64 },

    #[error("Invalid tip transaction (must be eip1559)")]
    InvalidTipTransaction,

    #[error("Invalid blob")]
    InvalidBlob,

    #[error("Missing sidecar in eip 4884 transaction")]
    Eip4884WithoutSidecar,

    #[error("Gas limit {gas_limit} exceeds reserved gas limit {reserved_gas_limit}")]
    ReservedGasLimitExceeded { gas_limit: u64, reserved_gas_limit: u64 },

    #[error("{0}")]
    BlobTransactionValidationError(#[from] alloy_consensus::BlobTransactionValidationError),

    #[error("{0}")]
    Signature(#[from] alloy_primitives::SignatureError),

    #[error("{0}")]
    ToStr(#[from] reqwest::header::ToStrError),

    #[error("{0}")]
    IO(#[from] std::io::Error),

    #[error("{0}")]
    Underwriter(#[from] UnderwriterError),

    #[error("{0}")]
    TxCache(#[from] TxCacheError),

    #[error("{0}")]
    Parse(#[from] url::ParseError),

    #[error("{0}")]
    Stream(#[from] StreamError),

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

    #[error("{0}")]
    Account(#[from] crate::account_state::AccountError),
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
    pub underwriter: Arc<RwLock<Underwriter>>,
    pub last_slot: Arc<AtomicU64>,
    pub available_slots: Arc<RwLock<Vec<SlotInfo>>>,
    pub preconf_fee_provider: Arc<RwLock<P>>,
    pub tx_cache: TxCachePerSlot,
    pub id_to_slot: Arc<RwLock<HashMap<Uuid, u64>>>,
    pub broadcast_sender: BroadcastSender,
    pub min_duration_until_next_slot: Duration,
    pub slot_model: SlotModel,
    pub account_state: AccountState<OnChainAccountInfoProvider>,
}

impl<P: PreconfFeeProvider> PreconfState<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        underwriter: Underwriter,
        last_slot: Arc<AtomicU64>,
        available_slots: Arc<RwLock<Vec<SlotInfo>>>,
        preconf_fee_provider: Arc<RwLock<P>>,
        tx_cache: TxCachePerSlot,
        broadcast_sender: BroadcastSender,
        slot_model: SlotModel,
        account_state: AccountState<OnChainAccountInfoProvider>,
    ) -> Self {
        Self {
            underwriter: Arc::new(underwriter.into()),
            last_slot,
            available_slots,
            preconf_fee_provider,
            tx_cache,
            id_to_slot: Arc::new(HashMap::new().into()),
            broadcast_sender,
            min_duration_until_next_slot: Duration::from_secs(1),
            slot_model,
            account_state,
        }
    }

    pub fn get_last_slot(&self) -> u64 {
        self.last_slot.load(Ordering::Relaxed)
    }

    pub fn verify_slot_in_future(&self, slot: u64) -> PreconfApiResult<()> {
        let last = self.get_last_slot();
        if slot <= last {
            return Err(PreconfApiError::SlotNotInFuture { slot, last });
        }
        Ok(())
    }

    pub async fn verify_slot_available(&self, slot: u64) -> PreconfApiResult<()> {
        if !self.available_slots.read().await.iter().any(|info| info.slot == slot) {
            return Err(PreconfApiError::SlotNotAvailable { slot });
        }
        Ok(())
    }

    pub fn verify_within_deadline(&self, slot: u64) -> PreconfApiResult<()> {
        let now_since_epoch =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Invalid time before epoch");
        let time_until_next_slot_start = self.slot_model.get_next_slot_start_offset(slot);
        if time_until_next_slot_start < now_since_epoch + self.min_duration_until_next_slot {
            return Err(PreconfApiError::DeadlineExpired {
                deadline: time_until_next_slot_start.as_secs(),
                received: now_since_epoch.as_secs(),
            });
        }
        Ok(())
    }
}

fn verify_preconfirmation_transactions_available(
    request: &SubmitTypeATransactionRequest,
) -> PreconfApiResult<()> {
    if request.preconf_transaction.is_empty() {
        return Err(PreconfApiError::MissingTransactions);
    }
    Ok(())
}

fn verify_blobs(txs: &[TxEnvelope]) -> PreconfApiResult<()> {
    let env_kzg_settings: EnvKzgSettings = EnvKzgSettings::default();
    let _ = txs
        .iter()
        .filter(|tx| tx.is_eip4844())
        .map(|tx| {
            Ok::<(), PreconfApiError>(
                tx.as_eip4844()
                    .expect("Failed to decode 4844 transaction")
                    .tx()
                    .clone()
                    .try_into_4844_with_sidecar()
                    .map_err(|_| PreconfApiError::Eip4884WithoutSidecar)?
                    .validate_blob(env_kzg_settings.get())?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

fn verify_reserved_gas_limit(gas_limit: u64, reserved_gas_limit: u64) -> PreconfApiResult<()> {
    if gas_limit > reserved_gas_limit {
        return Err(PreconfApiError::ReservedGasLimitExceeded { gas_limit, reserved_gas_limit });
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
    taiyi_escrow_address: Address,
    fork_version: [u8; 4],
) -> PreconfApiResult<()> {
    println!("run...");

    let genesis_timestamp = HOLESKY_GENESIS_TIMESTAMP;
    let genesis_since_epoch = Duration::from_secs(genesis_timestamp);
    let slot_duration = Duration::from_secs(12);
    let slots_per_epoch = 32u64;
    let epoch_duration = Duration::from_secs(slot_duration.as_secs() * slots_per_epoch);

    let taiyi_addr = SocketAddr::new(taiyi_rpc_addr, taiyi_rpc_port);
    let beacon_provider = ProviderBuilder::new().connect_http(Url::from_str(&beacon_rpc_url)?);
    let execution_provider =
        ProviderBuilder::new().connect_http(Url::from_str(&execution_rpc_url)?);
    let signer =
        PrivateKeySigner::from_signing_key(SigningKey::from_slice(&hex_decode(&ecdsa_sk)?)?);

    let chain_id = beacon_provider.get_chain_id().await?;

    let available_slots = Arc::new(RwLock::<Vec<SlotInfo>>::new(vec![]));
    let underwriter = Underwriter::new(available_slots.clone());

    let last_slot = Arc::new(AtomicU64::new(0u64));
    let preconf_fee_provider =
        Arc::new(RwLock::new(TaiyiPreconfFeeProvider::new(taiyi_service_url)));
    let tx_cache = TxCachePerSlot::new();
    let broadcast_sender = BroadcastSender::new(signer.clone(), chain_id, last_slot.clone());
    let slot_model = SlotModel::new(genesis_since_epoch, slot_duration, epoch_duration);

    let taiyi_escrow = TaiyiEscrowInstance::new(taiyi_escrow_address, execution_provider.clone());
    let state_provider = OnChainAccountInfoProvider::new(execution_rpc_url.clone(), taiyi_escrow);
    let account_state = AccountState::new(last_slot.clone(), state_provider);

    let state = Arc::new(PreconfState::new(
        underwriter,
        last_slot.clone(),
        available_slots.clone(),
        preconf_fee_provider,
        tx_cache.clone(),
        broadcast_sender,
        slot_model.clone(),
        account_state,
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
    let now_since_genesis = now_since_epoch - genesis_since_epoch;
    let start = get_next_slot_start(&now_since_genesis, &slot_duration)?;
    let slot = slot_model.get_slot(now_since_epoch);
    let next_slot_count = slot.epoch * slots_per_epoch + slot.slot + 1;
    let slot_stream = get_slot_stream(start, next_slot_count, slot_duration)?;

    let bls_private_key =
        SecretKey::from_bytes(&hex_decode(&bls_sk).map_err(PreconfApiError::from)?)?;
    let alloy_bls_public_key = bls_pubkey_to_alloy(&bls_private_key.sk_to_pk());
    let store_last_slot = StoreLastSlotDecorator::new(last_slot, Noop::new());
    let epoch_lookahead = 2;
    let store_last_slot = StoreAvailableSlotsDecorator::new(
        beacon_rpc_url.clone(),
        alloy_bls_public_key,
        Arc::new(vec![].into()),
        slots_per_epoch,
        epoch_lookahead,
        store_last_slot,
        HoleskySlotInfoFactory::default(),
    );
    let event_stream = get_event_stream(&beacon_rpc_url).await?;
    let listener = TcpListener::bind(&taiyi_addr).await?;

    let bls_signer =
        BlsSigner::new(signer.address(), Some(chain_id), bls_private_key, fork_version);

    tokio::select!(
        _ = axum::serve(listener, app) => { println!("terminating server") },
        _ = process_event_stream(event_stream, store_last_slot) => { println!("terminating event stream")},
        _ = submit_constraints(taiyi_core, slot_stream, execution_provider, tx_cache.clone(), signer, bls_signer, relay_url, slots_per_epoch) => { println!("terminating constraint stream")}
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
    state.verify_slot_in_future(target_slot)?;
    state.verify_slot_available(target_slot).await?;

    let expected_preconf_fee =
        state.preconf_fee_provider.read().await.get(request.target_slot).await?;
    if request.preconf_fee != expected_preconf_fee {
        return Err(PreconfApiError::InvalidPreconfFee {
            fee: request.preconf_fee,
            expected: expected_preconf_fee,
        });
    }

    let expected_tip = expected_preconf_fee.compute_tip(request.gas_limit, request.blob_count);
    verify_tip(request.preconf_tip(), expected_tip)?;
    state.account_state.verify_sufficient_balance(&signer, request.preconf_tip()).await?;
    state
        .underwriter
        .write()
        .await
        .reserve_blockspace(target_slot, request.gas_limit, request.blob_count)
        .await?;
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

    verify_preconfirmation_transactions_available(&request)?;
    state.verify_within_deadline(request.target_slot)?;
    if !request.tip_transaction.is_eip1559() {
        return Err(PreconfApiError::InvalidTipTransaction);
    }
    verify_blobs(&request.preconf_transaction)?;
    state.account_state.reserve(&signer, request.tip_transaction.nonce(), request.value()).await?;

    let preconf_fee = state.preconf_fee_provider.read().await.get(request.target_slot).await?;

    let id = Uuid::new_v4();
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
    let (signer, _) = get_signer_and_signature(headers, request.digest())?;
    info!("Received slot reservation request without calldata");

    let slot = state
        .id_to_slot
        .write()
        .await
        .remove(&request.request_id)
        .ok_or(PreconfApiError::UnknownId { id: request.request_id })?;
    let mut tx_cache = state.tx_cache.clone();
    verify_blobs(&[request.transaction.clone()])?;
    let request_gas_limit = request.transaction.gas_limit();
    let nonce = request.transaction.nonce();
    let amount = request.transaction.value();
    let preconf_request =
        tx_cache.add_calldata(slot, request.request_id, request.transaction).await?;
    state.verify_within_deadline(preconf_request.target_slot())?;
    verify_reserved_gas_limit(request_gas_limit, preconf_request.allocation.gas_limit)?;
    state.account_state.reserve(&signer, nonce, amount).await?;

    state
        .broadcast_sender
        .sign_and_send(request.request_id, PreconfRequest::TypeB(preconf_request))
        .await?;
    Ok(Json(()))
}

pub async fn get_available_slots<P: PreconfFeeProvider>(
    State(state): State<Arc<PreconfState<P>>>,
) -> PreconfApiResult<Json<Vec<SlotInfo>>> {
    let slots = state.available_slots.read().await;
    Ok(Json(slots.clone()))
}

pub async fn get_preconf_fee<P: PreconfFeeProvider>(
    State(state): State<Arc<PreconfState<P>>>,
    Json(slot): Json<u64>,
) -> PreconfApiResult<Json<PreconfFee>> {
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
