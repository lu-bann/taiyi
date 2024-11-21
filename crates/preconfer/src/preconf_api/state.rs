use std::{future::Future, sync::Arc, time::Duration};

use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{keccak256, U256};
use alloy_provider::Provider;
use alloy_signer::{Signature as ECDSASignature, Signer};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::Transport;
use ethereum_consensus::{
    altair::genesis,
    clock::{from_system_time, Clock},
    deneb::Context,
};
use futures::StreamExt;
use taiyi_primitives::{
    CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage, PreconfHash, PreconfRequest,
    PreconfResponse, PreconfStatus, PreconfStatusResponse, PreconfTx,
};
use tracing::{debug, error, info, warn};

use crate::{
    constraint_client::ConstraintClient,
    error::{PoolError, RpcError, ValidationError},
    network_state::NetworkState,
    preconf_pool::{PoolState, PreconfPool, PreconfPoolBuilder},
    pricer::PreconfPricer,
};

pub const SET_CONSTRAINTS_CUTOFF_NS: i64 = 8_000_000_000;
pub const SET_CONSTRAINTS_CUTOFF_NS_DELTA: i64 = -1_000_000_000;

#[derive(Clone)]
pub struct PreconfState {
    constraint_client: ConstraintClient,
    network_state: NetworkState,
    preconf_pool: Arc<PreconfPool>,
    context: Context,
    bls_sk: blst::min_pk::SecretKey,
    ecdsa_signer: PrivateKeySigner,
}

impl PreconfState {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        network_state: NetworkState,
        constraint_client: ConstraintClient,
        context: Context,
        bls_sk: blst::min_pk::SecretKey,
        ecdsa_signer: PrivateKeySigner,
    ) -> Self {
        let slot = network_state.get_current_slot();
        let preconf_pool = PreconfPoolBuilder::new().build(slot);
        Self { constraint_client, network_state, preconf_pool, context, bls_sk, ecdsa_signer }
    }

    pub fn preconf_requests(&self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.preconf_pool.preconf_requests()
    }

    // async fn signed_constraints_message(
    //     &self,
    //     constraints_message: ConstraintsMessage,
    // ) -> Result<SignedConstraintsMessage, RpcError> {
    //     let domain = compute_builder_domain(&self.context)
    //         .map_err(|e| RpcError::UnknownError(e.to_string()))?;
    //     let signing_root = compute_signing_root(&constraints_message, domain)
    //         .map_err(|e| RpcError::SignatureError(e.to_string()))?;
    //     let signature = self.bls_sk.sign(&signing_root.0, BLS_DST_SIG, &[]).to_bytes();
    //     let signature = Signature::try_from(signature.as_ref())
    //         .map_err(|e| RpcError::SignatureError(e.to_string()))?;

    //     Ok(SignedConstraintsMessage::new(constraints_message, signature))
    // }

    #[allow(unreachable_code)]
    pub fn spawn_constraint_submitter(self) -> impl Future<Output = eyre::Result<()>> {
        let constraint_client = self.constraint_client.clone();
        let genesis_time = match self.context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.context.min_genesis_time + self.context.genesis_delay,
        };

        async move {
            // wait for 3 seconds to let the first network state slot to be initialized
            // this is a temporary solution to let the first network state slot to be initialized
            tokio::time::sleep(Duration::from_secs(3)).await;
            let mut last_slot = self.network_state.get_current_slot();
            loop {
                let slot = self.network_state.get_current_slot();
                debug!("current slot: {slot}, last slot: {last_slot}");
                if slot == last_slot {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                let slot_start_timestamp =
                    (genesis_time + (slot * self.context.seconds_per_slot)) * 1_000_000_000;
                let submit_start_time = slot_start_timestamp as i64
                    + SET_CONSTRAINTS_CUTOFF_NS
                    + SET_CONSTRAINTS_CUTOFF_NS_DELTA;
                let sleep_duration = submit_start_time
                    - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
                info!(
                    "Current time: {}, Slot start time: {}, Submit start time: {}",
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
                    slot_start_timestamp,
                    submit_start_time
                );
                info!("Sleep duration: {}", sleep_duration / 1_000_000_000);
                if sleep_duration.is_positive() {
                    info!("Sleeping for {} s until slot {} starts", sleep_duration, slot + 1);
                    tokio::time::sleep(Duration::from_nanos(
                        sleep_duration.try_into().expect("positive sleep duration"),
                    ))
                    .await;
                } else {
                    warn!("slot is in past, skipping");
                    continue;
                }

                // get all the preconf requests from the ready pool
                let preconf_requests = self.preconf_requests()?;

                if preconf_requests.is_empty() {
                    last_slot = slot;
                    continue;
                } else {
                    let _wallet = EthereumWallet::new(self.ecdsa_signer.clone());
                    let signed_constraints_message = Vec::new();
                    // info!(
                    //     "Sending {} constraints message with slot: {}",
                    //     constraint_message.len(),
                    //     constraint_message.slot
                    // );
                    // let signed_constraints_message = self
                    //     .signed_constraints_message(constraint_message)
                    //     .await
                    //     .expect("signed constraints");
                    let max_retries = 5;
                    let mut i = 0;

                    'submit: while let Err(e) = constraint_client
                        .send_set_constraints(
                            signed_constraints_message.clone(),
                            slot_start_timestamp,
                        )
                        .await
                    {
                        error!(err = ?e, "Error submitting constraints to relay, retrying...");
                        i += 1;
                        if i >= max_retries {
                            error!("Max retries reached while submitting to MEV-Boost");
                            break 'submit;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }

                last_slot = slot;
            }
            Ok(())
        }
    }

    pub async fn sign_tip_tx_signature(
        &self,
        tip_tx_signature: &ECDSASignature,
    ) -> Result<ECDSASignature, RpcError> {
        let message = tip_tx_signature.as_bytes().to_vec();
        let message = keccak256(&message);
        let signature = self
            .ecdsa_signer
            .sign_hash(&message)
            .await
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;
        Ok(signature)
    }

    /// Send a preconf request to the preconfer
    ///
    /// Expected forms
    ///     - PreconfRequest without PreconfTx
    ///     - PreconfRequest with PreconfTx
    pub async fn send_preconf_request(
        &self,
        mut preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        let chain_id = self.get_chain_id().await?;
        let current_slot = self.network_state.get_current_slot();
        // TODO: currently only reqs for the Ready sub-pool are accepted, change this later.
        // Note: It is assumed that there're no other requests from the same sender in the same slot
        // PreconfTx must be present
        if preconf_request.preconf_tx.is_none() {
            return Err(RpcError::UnknownError("PreconfTx must be present".to_string()));
        }

        // Target slot must be the next slot
        if preconf_request.tip_tx.target_slot != U256::from(current_slot + 1) {
            return Err(RpcError::UnknownError("Target slot must be the next slot".to_string()));
        }

        let preconf_hash = preconf_request.hash(U256::from(chain_id));
        let preconfer_signature =
            self.sign_tip_tx_signature(&preconf_request.tip_tx_signature).await?;
        preconf_request.preconfer_signature = Some(preconfer_signature);

        let preconf_req_hash = preconf_request.preconf_req_hash(U256::from(chain_id)).ok_or(
            RpcError::UnknownError(format!(
                "Failed to get preconf req hash from {preconf_request:?}",
            )),
        )?;

        match self.preconf_pool.request_inclusion(preconf_request.clone(), chain_id) {
            Ok(PoolState::Ready) | Ok(PoolState::Pending) => {
                let preconf_req_signature = self
                    .ecdsa_signer
                    .sign_hash(&preconf_req_hash)
                    .await
                    .map_err(|err| RpcError::SignatureError(err.to_string()))?;
                preconf_request.preconf_req_signature = Some(preconf_req_signature);

                Ok(PreconfResponse::success(
                    preconf_hash,
                    preconfer_signature,
                    Some(preconf_req_signature),
                ))
            }
            Ok(PoolState::Parked) => {
                Ok(PreconfResponse::success(preconf_hash, preconfer_signature, None))
            }
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn cancel_preconf_request(
        &self,
        _cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, PoolError> {
        unimplemented!()
    }

    pub async fn send_preconf_tx_request(
        &self,
        preconf_req_hash: PreconfHash,
        preconf_tx: PreconfTx,
    ) -> Result<PreconfResponse, RpcError> {
        let chain_id = self.get_chain_id().await?;
        let mut preconf_request = self
            .preconf_pool
            .get_parked(&preconf_req_hash)
            .ok_or(PoolError::PreconfRequestNotFound(preconf_req_hash))?;
        if preconf_request.preconf_tx.is_some() {
            return Err(RpcError::PreconfTxAlreadySet(preconf_req_hash));
        }
        preconf_request.preconf_tx = Some(preconf_tx.clone());

        match self.preconf_pool.request_inclusion(preconf_request.clone(), chain_id) {
            Ok(PoolState::Ready) | Ok(PoolState::Pending) => {
                let preconf_req_signature = self
                    .ecdsa_signer
                    .sign_hash(&preconf_req_hash)
                    .await
                    .map_err(|err| RpcError::SignatureError(err.to_string()))?;
                preconf_request.preconf_req_signature = Some(preconf_req_signature);

                Ok(PreconfResponse::success(
                    preconf_req_hash,
                    preconf_request.preconfer_signature.expect("preconfer signature"),
                    Some(preconf_req_signature),
                ))
            }
            Err(PoolError::InvalidPreconfTx(_)) => {
                self.preconf_pool.delete_parked(&preconf_req_hash);
                Err(RpcError::PreconfRequestError("Invalid preconf tx".to_string()))
            }
            _ => Err(RpcError::UnknownError("Invalid pool state".to_string())),
        }
    }

    pub async fn check_preconf_request_status(
        &self,
        preconf_hash: PreconfHash,
    ) -> Result<PreconfStatusResponse, PoolError> {
        let pool = self.preconf_pool.get_pool(&preconf_hash)?;
        let status = match pool {
            PoolState::Parked => PreconfStatus::Pending,
            PoolState::Pending => PreconfStatus::Pending,
            PoolState::Ready => PreconfStatus::Accepted,
        };
        Ok(PreconfStatusResponse { status })
    }

    pub async fn get_slots(&self) -> Result<Vec<u64>, RpcError> {
        let current_slot = self.network_state.get_current_slot();
        let available_slots = self
            .network_state
            .get_proposer_duties()
            .iter()
            .map(|duty| duty.slot)
            .filter(|slot| *slot > current_slot)
            .collect();
        Ok(available_slots)
    }

    async fn get_chain_id(&self) -> Result<u64, RpcError> {
        Ok(1)
    }
}
