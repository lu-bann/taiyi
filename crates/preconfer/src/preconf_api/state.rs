use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{keccak256, PrimitiveSignature};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::Transport;
use ethereum_consensus::{
    altair::genesis,
    clock::{from_system_time, Clock},
    deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, Context},
    primitives::BlsPublicKey,
    ssz::prelude::ByteList,
};
use futures::StreamExt;
use reth_primitives::PooledTransaction;
use serde::{Deserialize, Serialize};
use taiyi_primitives::{
    CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage, ContextExt, PreconfRequest,
    PreconfResponse, PreconfStatus, PreconfStatusResponse, SignableBLS, SignedConstraints,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    clients::{relay_client::RelayClient, signer_client::SignerClient},
    error::{PoolError, RpcError},
    network_state::NetworkState,
    preconf_pool::{BlockspaceAvailable, PoolType, PreconfPool, PreconfPoolBuilder},
    pricer::PreconfPricer,
};

#[derive(Clone)]
pub struct PreconfState {
    relay_client: RelayClient,
    network_state: NetworkState,
    preconf_pool: Arc<PreconfPool>,
    signer_client: SignerClient,
    rpc_url: String,
}

impl PreconfState {
    pub fn new(
        network_state: NetworkState,
        relay_client: RelayClient,
        signer_client: SignerClient,
        rpc_url: String,
    ) -> Self {
        let slot = network_state.get_current_slot();
        let preconf_pool = PreconfPoolBuilder::new().build(slot);

        Self { relay_client, network_state, preconf_pool, signer_client, rpc_url }
    }

    pub fn preconf_requests(&self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.preconf_pool.preconf_requests()
    }

    fn deadline_of_slot(&self, slot: u64) -> u64 {
        let context = self.network_state.get_context();
        context.get_deadline_of_slot(slot)
    }

    pub fn spawn_constraint_submitter(self) -> impl Future<Output = eyre::Result<()>> {
        let relay_client = self.relay_client.clone();
        let context = self.network_state.get_context();
        let genesis_time = match context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => context.min_genesis_time + context.genesis_delay,
        };

        async move {
            let clock =
                from_system_time(genesis_time, context.seconds_per_slot, context.slots_per_epoch);
            let mut slot_stream = clock.into_stream();
            while let Some(slot) = slot_stream.next().await {
                let next_slot = slot + 1;

                let submit_constraint_deadline_duration =
                    self.deadline_of_slot(next_slot).saturating_sub(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs(),
                    );
                tokio::time::sleep(Duration::from_secs(submit_constraint_deadline_duration)).await;
                match self.preconf_pool.pending_requests(next_slot) {
                    Ok(preconf_requests) => {
                        if preconf_requests.is_empty() {
                            continue;
                        }
                        let mut txs = Vec::new();
                        for preconf_req in preconf_requests {
                            if let Some(tx) = preconf_req.transaction {
                                let mut tx_bytes = Vec::new();
                                tx.encode_2718(&mut tx_bytes);
                                let tx_ref: &[u8] = tx_bytes.as_ref();
                                let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                                    tx_ref.try_into().expect("tx bytes too big");
                                txs.push(tx_bytes);
                            }
                        }
                        let txs_len = txs.len();
                        let bls_pk = self.signer_client.bls_pubkey();
                        let message = ConstraintsMessage {
                            pubkey: BlsPublicKey::try_from(bls_pk.to_bytes().as_ref())
                                .expect("key error"),
                            slot: next_slot,
                            top: true,
                            transactions: txs.try_into().expect("tx too big"),
                        };
                        let digest = message.digest();
                        if let Ok(signature) =
                            self.signer_client.sign_with_bls(context.clone(), digest)
                        {
                            let signed_constraints_message =
                                vec![SignedConstraints { message, signature }];

                            let max_retries = 5;
                            let mut i = 0;

                            info!("Submitting {txs_len} constraints to relay on  slot {next_slot}");
                            'submit: while let Err(e) = relay_client
                                .set_constraints(signed_constraints_message.clone())
                                .await
                            {
                                error!(err = ?e, "Error submitting constraints to relay, retrying...");
                                i += 1;
                                if i >= max_retries {
                                    error!("Max retries reached while submitting to relay");
                                    break 'submit;
                                }
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                    Err(_) => {
                        debug!("No requests found for slot: {}", next_slot);
                        continue;
                    }
                }
                self.preconf_pool.remove_account_state(next_slot);
            }
            Ok(())
        }
    }

    /// Send a preconf request to the preconfer
    ///
    /// Expected forms
    ///     - PreconfRequest without transaction
    ///     - PreconfRequest with transaction
    pub async fn request_preconf(
        &self,
        preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        // TODO: check for sender's collateral
        // A sender must have enough collateral to cover for the penalty imposed by the preconfer on
        // the sender if the sender fails to submit the preconf_tx

        let request_id = Uuid::new_v4();

        if self.is_exceed_deadline(preconf_request.target_slot) {
            return Err(RpcError::ExceedDeadline(preconf_request.target_slot));
        }

        match self
            .preconf_pool
            .request_inclusion(preconf_request.clone(), request_id, self.rpc_url.clone())
            .await
        {
            Ok(PoolType::Ready) | Ok(PoolType::Pending) => {
                let message_digest = {
                    let mut data = Vec::new();
                    // First field is the concatenation of the transaction hash
                    data.extend_from_slice(
                        preconf_request
                            .transaction
                            .expect("preconf tx not found")
                            .tx_hash()
                            .as_slice(),
                    );

                    // Second field is the little endian encoding of the target slot
                    data.extend_from_slice(&preconf_request.target_slot.to_le_bytes());
                    keccak256(data)
                };
                let commitment =
                    self.signer_client.sign_with_ecdsa(message_digest).await.map_err(|e| {
                        RpcError::SignatureError(format!("Failed to issue commitment: {e:?}"))
                    })?;
                Ok(PreconfResponse::success(request_id, Some(commitment)))
            }
            Ok(PoolType::Parked) => Ok(PreconfResponse::success(request_id, None)),
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn cancel_preconf_request(
        &self,
        _cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, PoolError> {
        unimplemented!()
    }

    pub async fn preconf_transaction(
        &self,
        request_id: Uuid,
        transaction: TxEnvelope,
    ) -> Result<PreconfResponse, RpcError> {
        let mut preconf_request = self
            .preconf_pool
            .get_parked(request_id)
            .ok_or(PoolError::PreconfRequestNotFound(request_id))?;
        if preconf_request.transaction.is_some() {
            return Err(RpcError::PreconfTxAlreadySet);
        }
        if self.is_exceed_deadline(preconf_request.target_slot) {
            return Err(RpcError::ExceedDeadline(preconf_request.target_slot));
        }
        preconf_request.transaction = Some(transaction.clone());

        match self
            .preconf_pool
            .request_inclusion(preconf_request.clone(), request_id, self.rpc_url.clone())
            .await
        {
            Ok(PoolType::Ready) | Ok(PoolType::Pending) => {
                let message_digest = {
                    let mut data = Vec::new();
                    // First field is the concatenation of the transaction hash
                    data.extend_from_slice(
                        preconf_request
                            .transaction
                            .expect("preconf tx not found")
                            .tx_hash()
                            .as_slice(),
                    );

                    // Second field is the little endian encoding of the target slot
                    data.extend_from_slice(&preconf_request.target_slot.to_le_bytes());
                    keccak256(data)
                };
                let commitment =
                    self.signer_client.sign_with_ecdsa(message_digest).await.map_err(|e| {
                        RpcError::SignatureError(format!("Failed to issue commitment: {e:?}"))
                    })?;
                Ok(PreconfResponse::success(request_id, Some(commitment)))
            }
            Ok(PoolType::Parked) => Err(RpcError::UnknownError(
                "Preconf request shouldn't be in Parked subpool".to_string(),
            )),
            Err(PoolError::InvalidPreconfTx(_)) => {
                self.preconf_pool.delete_parked(request_id);
                // TODO penalize the sender
                // self.preconfer.taiyi_core_contract.exhaust(preconf_request.into()).call().await?;
                Err(RpcError::PreconfRequestError("Invalid preconf tx".to_string()))
            }
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn check_preconf_request_status(
        &self,
        request_id: Uuid,
    ) -> Result<PreconfStatusResponse, PoolError> {
        let pool = self.preconf_pool.get_pool(request_id)?;
        let status = match pool {
            PoolType::Parked => PreconfStatus::Pending,
            PoolType::Pending => PreconfStatus::Pending,
            PoolType::Ready => PreconfStatus::Accepted,
        };
        Ok(PreconfStatusResponse { status })
    }

    pub async fn get_slots(&self) -> Result<Vec<GetSlotResponse>, RpcError> {
        let current_slot = self.network_state.get_current_slot();

        let slot_diff = if self.is_exceed_deadline(current_slot) { 1 } else { 0 };
        let available_slots = self
            .network_state
            .available_slots()
            .into_iter()
            .filter(|slot| *slot > current_slot + slot_diff)
            .map(|slot| GetSlotResponse {
                slot,
                blockspace_available: self.preconf_pool.blockspace_available(slot),
            })
            .collect();

        Ok(available_slots)
    }

    fn is_exceed_deadline(&self, slot: u64) -> bool {
        let utc_timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("after `UNIX_EPOCH`").as_secs();
        let deadline = self.deadline_of_slot(slot);
        utc_timestamp > deadline
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct GetSlotResponse {
    pub slot: u64,
    pub blockspace_available: BlockspaceAvailable,
}
