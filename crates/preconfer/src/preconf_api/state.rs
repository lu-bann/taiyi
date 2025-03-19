use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_consensus::Transaction;
use alloy_primitives::{Address, PrimitiveSignature};
use alloy_provider::Provider;
use reqwest::Url;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfRequestTypeA, PreconfRequestTypeB, PreconfResponse, SlotInfo,
    SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use uuid::Uuid;

use crate::{
    clients::{relay_client::RelayClient, signer_client::SignerClient},
    context_ext::ContextExt,
    error::{PoolError, RpcError},
    network_state::NetworkState,
    preconf_pool::{PreconfPool, PreconfPoolBuilder},
};

#[derive(Clone)]
pub struct PreconfState<P> {
    pub network_state: NetworkState,
    pub preconf_pool: Arc<PreconfPool>,
    pub relay_client: RelayClient,
    pub signer_client: SignerClient,
    pub provider: P,
    pub min_fee_per_gas: u128,
}

impl<P> PreconfState<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_state: NetworkState,
        relay_client: RelayClient,
        signer_client: SignerClient,
        execution_rpc_url: Url,
        taiyi_escrow_address: Address,
        provider: P,
        min_fee_per_gas: u128,
    ) -> Self {
        let preconf_pool = PreconfPoolBuilder::new().build(execution_rpc_url, taiyi_escrow_address);
        Self { relay_client, network_state, preconf_pool, signer_client, provider, min_fee_per_gas }
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
        // Check if the gateway is delegated for the target slot
        if !self.network_state.contains_slot(request.target_slot) {
            return Err(RpcError::SlotNotAvailable(request.target_slot));
        }

        // TODO: Check gas_fee & blob_gas_fee against the pricing service

        let current_slot = self.network_state.get_current_slot();
        // Target slot must be atleast current slot + 2
        // Current + 1 slot transactions should use Type A transactions directly
        // Reservation is only for slots with 2+ slot delay
        if request.target_slot < current_slot + 1 {
            return Err(RpcError::ExceedDeadline(request.target_slot));
        }

        if request.gas_limit == 0 {
            return Err(RpcError::UnknownError("Gas limit cannot be zero".to_string()));
        }

        // Construct a preconf request
        let preconf_request =
            PreconfRequestTypeB { allocation: request, alloc_sig, transaction: None, signer };

        self.preconf_pool.reserve_blockspace(preconf_request).await.map_err(RpcError::PoolError)
    }

    pub async fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
        signature: PrimitiveSignature,
    ) -> Result<PreconfResponse, RpcError> {
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
            return Err(RpcError::UnknownError(
                "Gas limit exceeds reserved blockspace".to_string(),
            ));
        }

        // Check for gas fee caps
        if request.transaction.max_fee_per_gas() < self.min_fee_per_gas {
            return Err(RpcError::MaxFeePerGasLessThanThreshold(
                self.min_fee_per_gas,
                request.transaction.max_fee_per_gas(),
            ));
        }

        preconf_request.transaction = Some(request.transaction.clone());

        let chain_id = self
            .provider
            .get_chain_id()
            .await
            .map_err(|_| RpcError::UnknownError("Failed to get chain id".to_string()))?;

        match self
            .preconf_pool
            .validate_and_store(
                taiyi_primitives::PreconfRequest::TypeB(preconf_request.clone()),
                request.request_id,
            )
            .await
        {
            Ok(result) => {
                let commitment =
                    self.signer_client.sign_with_ecdsa(result.digest(chain_id)).await.map_err(
                        |e| RpcError::SignatureError(format!("Failed to issue commitment: {e:?}")),
                    )?;
                Ok(PreconfResponse::success(request.request_id, Some(commitment), None))
            }
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn submit_typea_transaction(
        &self,
        request: SubmitTypeATransactionRequest,
        signature: PrimitiveSignature,
        signer: Address,
    ) -> Result<PreconfResponse, RpcError> {
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
            return Err(RpcError::UnknownError("No preconf transactions".to_string()));
        }

        // Only for internal use.
        let request_id = Uuid::new_v4();
        let preconf_request = PreconfRequestTypeA {
            preconf_tx: request.clone().preconf_transaction,
            tip_transaction: request.clone().tip_transaction,
            target_slot: request.target_slot,
            sequence_number: None,
            signer,
        };

        let chain_id = self
            .provider
            .get_chain_id()
            .await
            .map_err(|_| RpcError::UnknownError("Failed to get chain id".to_string()))?;

        match self
            .preconf_pool
            .validate_and_store(
                taiyi_primitives::PreconfRequest::TypeA(preconf_request.clone()),
                request_id,
            )
            .await
        {
            Ok(result) => {
                let commitment =
                    self.signer_client.sign_with_ecdsa(result.digest(chain_id)).await.map_err(
                        |e| RpcError::SignatureError(format!("Failed to issue commitment: {e:?}")),
                    )?;
                Ok(PreconfResponse::success(request_id, Some(commitment), result.sequence_num()))
            }
            Err(e) => Err(RpcError::PoolError(e)),
        }
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
