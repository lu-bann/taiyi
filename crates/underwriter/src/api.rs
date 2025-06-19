use std::{
    future::Future,
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use alloy_primitives::{Address, Signature, B256};
use axum::{
    extract::State,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use reqwest::{header::HeaderMap, StatusCode};
use serde_json::json;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeResponse, PreconfRequestTypeB, SlotInfo,
    SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    block_info::{BlockInfo, BlockInfoError},
    underwriter::{DummySender, Underwriter, UnderwriterError},
};

const AVAILABLE_SLOTS: &str = "/commitments/v0/slots";
const PRECONF_FEE: &str = "/commitments/v0/preconf_fee";
const RESERVE_BLOCKSPACE: &str = "/commitments/v0/reserve_blockspace";
const RESERVE_SLOT_WITH_CALLDATA: &str = "/commitments/v0/submit_tx_type_a";
const RESERVE_SLOT_WITHOUT_CALLDATA: &str = "/commitments/v0/submit_tx_type_b";
//const COMMITMENT_STREAM: &str = "/commitments/v0/commitment_stream";

#[derive(Debug, Error)]
pub enum PreconfApiError {
    #[error("Missing header for {key}")]
    MissingHeader { key: String },

    #[error("Slot needs to be in the future. (slot={slot}, current={current})")]
    SlotNotInFuture { slot: u64, current: u64 },

    #[error("Slot not available. (slot={slot})")]
    SlotNotAvailable { slot: u64 },

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
}

impl<P: PreconfFeeProvider> PreconfState<P> {
    pub fn new(
        underwriter: Underwriter,
        current_slot: Arc<AtomicU64>,
        available_slots: Arc<RwLock<Vec<u64>>>,
        preconf_fee_provider: Arc<RwLock<P>>,
    ) -> Self {
        Self {
            underwriter: underwriter.into(),
            current_slot,
            available_slots,
            preconf_fee_provider,
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

pub async fn run(addr: SocketAddr) -> PreconfApiResult<()> {
    println!("run...");

    let gas_limit = 123456;
    let blob_limit = 1324;
    let constraint_limit = 12;
    let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
    let underwriter = Underwriter::new(reference_block_info);

    let current_slot = Arc::new(AtomicU64::new(0u64));
    let available_slots = Arc::new(RwLock::<Vec<u64>>::new(vec![]));
    let preconf_fee_provider = Arc::new(RwLock::new(DummyPreconfFeeProvider {}));
    let state = Arc::new(PreconfState::new(
        underwriter,
        current_slot,
        available_slots,
        preconf_fee_provider,
    ));
    let app = Router::new()
        .route("/health", get(health_check))
        .route(RESERVE_BLOCKSPACE, post(reserve_blockspace))
        .route(RESERVE_SLOT_WITH_CALLDATA, post(reserve_slot_with_calldata))
        .route(RESERVE_SLOT_WITHOUT_CALLDATA, post(reserve_slot_without_calldata))
        .route(AVAILABLE_SLOTS, get(get_available_slots))
        .route(PRECONF_FEE, post(get_preconf_fee))
        .with_state(state);
    // .route(COMMITMENT_STREAM, get(commitments_stream))
    // .layer(middleware::from_fn(metrics_middleware))

    println!("Starting rpc server...");
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
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

    state.assert_slot_in_future(request.target_slot)?;
    state.assert_slot_available(request.target_slot).await?;

    let id = Uuid::new_v4();

    let preconf_request = PreconfRequestTypeB {
        allocation: request,
        alloc_sig: signature,
        transaction: None,
        signer,
    };
    state.underwriter.write().await.reserve_transaction_with_blockspace(id, preconf_request)?;
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

    let preconf_fee = state.preconf_fee_provider.read().await.get(request.target_slot).await;
    let sender = DummySender {};
    state
        .underwriter
        .write()
        .await
        .reserve_slot_with_calldata(id, request, preconf_fee, sender, signer)
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

    let sender = DummySender {};
    state.underwriter.write().await.submit_reserved_transaction(request, sender).await?;
    Ok(Json(()))
}

#[cfg_attr(test, mockall::automock)]
pub trait PreconfFeeProvider {
    fn get(&self, slot: u64) -> impl Future<Output = PreconfFeeResponse>;
}

#[derive(Debug)]
pub struct DummyPreconfFeeProvider;

impl PreconfFeeProvider for DummyPreconfFeeProvider {
    async fn get(&self, _: u64) -> PreconfFeeResponse {
        PreconfFeeResponse { gas_fee: 10, blob_gas_fee: 150 }
    }
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
    Ok(Json(state.preconf_fee_provider.read().await.get(slot).await))
}
