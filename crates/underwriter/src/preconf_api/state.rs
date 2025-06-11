use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_consensus::Transaction;
use alloy_primitives::{hex, Address, PrimitiveSignature};
use alloy_provider::Provider;
use reqwest::Url;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfRequest, PreconfRequestTypeA, PreconfRequestTypeB,
    PreconfResponseData, SlotInfo, SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    clients::{pricer::PreconfPricer, relay_client::RelayClient, signer_client::SignerClient},
    context_ext::ContextExt,
    error::{PoolError, RpcError},
    network_state::NetworkState,
    preconf_pool::{create_preconf_pool, sequence_number::SequenceNumberPerSlot, PreconfPool},
};

pub fn send_commitment(
    sender: &broadcast::Sender<(PreconfRequest, PreconfResponseData)>,
    data: (PreconfRequest, PreconfResponseData),
) {
    match sender.send(data) {
        Ok(res) => info!("Sent data: {:?}", res),
        Err(_) => debug!("Failed to send data, no receivers available"),
    }
}

#[derive(Clone)]
pub struct PreconfState<P, F> {
    pub network_state: NetworkState,
    pub preconf_pool: Arc<PreconfPool>,
    pub relay_client: RelayClient,
    pub signer_client: SignerClient,
    pub provider: P,
    pub pricer: F,
    pub broadcast_sender: broadcast::Sender<(PreconfRequest, PreconfResponseData)>,
    sequence_number_per_slot: Arc<RwLock<SequenceNumberPerSlot>>,
}

impl<P, F> PreconfState<P, F>
where
    P: Provider + Clone + Send + Sync + 'static,
    F: PreconfPricer + Sync + Send + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_state: NetworkState,
        relay_client: RelayClient,
        signer_client: SignerClient,
        execution_rpc_url: Url,
        taiyi_escrow_address: Address,
        provider: P,
        pricer: F,
    ) -> Self {
        let preconf_pool = create_preconf_pool(execution_rpc_url, taiyi_escrow_address);

        let broadcast_sender = broadcast::channel(128).0;
        Self {
            relay_client,
            network_state,
            preconf_pool,
            signer_client,
            provider,
            pricer,
            broadcast_sender,
            sequence_number_per_slot: Arc::new(RwLock::new(SequenceNumberPerSlot::new())),
        }
    }

    /// reserve blockspace for a slot
    ///
    /// Requirements for target slot:
    /// 1. Must be at least 2 slots ahead of current slot
    pub async fn reserve_blockspace(
        &self,
        request: BlockspaceAllocation,
        alloc_sig: PrimitiveSignature,
        signer: Address,
    ) -> Result<Uuid, RpcError> {
        // Check if the underwriter is delegated for the target slot
        if !self.network_state.contains_slot(request.target_slot) {
            return Err(RpcError::SlotNotAvailable(request.target_slot));
        }

        let current_slot = self.network_state.get_current_slot();
        // Target slot must be atleast current slot + 2
        // Current + 1 slot transactions should use Type A transactions directly
        // Reservation is only for slots with 2+ slot delay
        if request.target_slot < current_slot + 1 {
            return Err(RpcError::ExceedDeadline(request.target_slot));
        }

        if request.gas_limit == 0 {
            return Err(RpcError::ParamsError("Gas limit cannot be zero".to_string()));
        }

        let preconf_fee = self.pricer.get_preconf_fee(request.target_slot).await?;

        if request.preconf_fee != preconf_fee {
            return Err(RpcError::ParamsError(
                "preconf_fee field does not match with currently quoted prices".to_string(),
            ));
        }

        // Construct a preconf request
        let preconf_request =
            PreconfRequestTypeB { allocation: request, alloc_sig, transaction: None, signer };

        self.preconf_pool
            .reserve_blockspace(preconf_request, preconf_fee)
            .await
            .map_err(RpcError::PoolError)
    }

    pub async fn submit_transaction_typeb(
        &self,
        request: SubmitTransactionRequest,
        signature: PrimitiveSignature,
    ) -> Result<PreconfResponseData, RpcError> {
        let mut preconf_request = self
            .preconf_pool
            .get_pending(request.request_id)
            .ok_or(PoolError::PreconfRequestNotFound(request.request_id))?;

        // Verify the signature
        let recovered_signer = signature
            .recover_address_from_prehash(&request.digest())
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;
        let signer = preconf_request.signer();
        if recovered_signer != signer {
            return Err(RpcError::SignatureError("Invalid signature".to_string()));
        }

        if preconf_request.transaction.is_some() {
            return Err(RpcError::PreconfTxAlreadySet);
        }

        if self.is_exceed_deadline(preconf_request.target_slot()) {
            return Err(RpcError::ExceedDeadline(preconf_request.target_slot()));
        }

        // Check if blocksapce reserved matches with transaction gas limit
        if preconf_request.allocation.gas_limit < request.transaction.gas_limit() {
            return Err(RpcError::ParamsError("Gas limit exceeds reserved blockspace".to_string()));
        }

        preconf_request.transaction = Some(request.transaction.clone());

        self.preconf_pool.validate_typeb(&preconf_request).await?;
        self.preconf_pool.delete_pending(request.request_id);
        let typeb_request = taiyi_primitives::PreconfRequest::TypeB(preconf_request);
        self.preconf_pool.insert_ready(request.request_id, typeb_request.clone());

        let commitment = self
            .signer_client
            .sign_with_ecdsa(typeb_request.digest(self.network_state.chain_id()))
            .await
            .map_err(|e| RpcError::InternalError(format!("Failed to issue commitment: {e:?}")))?;

        let preconf_response = PreconfResponseData {
            request_id: request.request_id,
            commitment: Some(format!("0x{}", hex::encode(commitment.as_bytes()))),
            sequence_num: None,
            current_slot: self.network_state.get_current_slot(),
        };
        // Send the commitment data to the stream
        send_commitment(&self.broadcast_sender, (typeb_request, preconf_response.clone()));
        Ok(preconf_response)
    }

    pub async fn submit_typea_transaction(
        &self,
        request: SubmitTypeATransactionRequest,
        signature: PrimitiveSignature,
        signer: Address,
    ) -> Result<PreconfResponseData, RpcError> {
        let recovered_signer = signature
            .recover_address_from_prehash(&request.digest())
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;

        if recovered_signer != signer {
            return Err(RpcError::SignatureError("Invalid signature".to_string()));
        }

        if self.is_exceed_deadline(request.target_slot) {
            return Err(RpcError::ExceedDeadline(request.target_slot));
        }

        if request.preconf_transaction.is_empty() {
            return Err(RpcError::ParamsError("No preconf transactions".to_string()));
        }

        let preconf_fee = self.pricer.get_preconf_fee(request.target_slot).await?;

        // Only for internal use.
        let request_id = Uuid::new_v4();
        let mut preconf_request = PreconfRequestTypeA {
            preconf_tx: request.clone().preconf_transaction,
            tip_transaction: request.clone().tip_transaction,
            target_slot: request.target_slot,
            sequence_number: None,
            signer,
            preconf_fee: preconf_fee.clone(),
        };
        self.preconf_pool.validate_typea(&preconf_request, &preconf_fee).await?;

        let sequence_number = Some(
            self.sequence_number_per_slot
                .write()
                .await
                .get_next_and_add(request.target_slot, request.preconf_transaction.len() as u64),
        );
        preconf_request.sequence_number = sequence_number;
        let typea_request = taiyi_primitives::PreconfRequest::TypeA(preconf_request.clone());
        self.preconf_pool.insert_ready(request_id, typea_request.clone());
        let commitment = self
            .signer_client
            .sign_with_ecdsa(typea_request.digest(self.network_state.chain_id()))
            .await
            .map_err(|e| RpcError::InternalError(format!("Failed to issue commitment: {e:?}")))?;

        let current_slot = self.network_state.get_current_slot();
        let commitment = PreconfResponseData {
            request_id,
            commitment: Some(format!("0x{}", hex::encode(commitment.as_bytes()))),
            sequence_num: sequence_number,
            current_slot,
        };
        // Send the commitment data to the stream
        send_commitment(&self.broadcast_sender, (typea_request, commitment.clone()));
        self.sequence_number_per_slot.write().await.remove_before(current_slot);
        Ok(commitment)
    }

    /// Returns the slots for which there is a opted in validator for current epoch and next epoch
    pub async fn get_slots(&self) -> Result<Vec<SlotInfo>, RpcError> {
        let current_slot = self.network_state.get_current_slot();

        let slot_diff = if self.is_exceed_deadline(current_slot) { 1 } else { 0 };

        let available_slots = self
            .network_state
            .available_slots()
            .into_iter()
            .filter(|slot| *slot >= current_slot + slot_diff)
            .map(|slot| {
                let blockspace_available = self.preconf_pool.blockspace_available(slot);
                SlotInfo {
                    slot,
                    gas_available: blockspace_available.gas_limit,
                    blobs_available: blockspace_available.blobs,
                    constraints_available: blockspace_available.num_of_constraints,
                }
            })
            .collect();

        Ok(available_slots)
    }

    fn is_exceed_deadline(&self, slot: u64) -> bool {
        let utc_timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("after `UNIX_EPOCH`").as_secs();
        let deadline = self.network_state.context().get_deadline_of_slot(slot);
        utc_timestamp > deadline
    }
}
