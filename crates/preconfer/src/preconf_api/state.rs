use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{keccak256, Address, PrimitiveSignature};
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_signer::{Signature as ECDSASignature, Signer};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::Transport;
use alloy_transport_http::{reqwest::Client, Http};
use ethereum_consensus::{
    altair::genesis,
    clock::{from_system_time, Clock},
    deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, Context},
    primitives::BlsPublicKey,
    ssz::prelude::ByteList,
};
use futures::StreamExt;
use reqwest::Url;
use reth_primitives::PooledTransaction;
use reth_revm::handler::execution;
use serde::{Deserialize, Serialize};
use taiyi_primitives::{
    BlockspaceAllocation, CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage,
    ContextExt, PreconfRequest, PreconfResponse, PreconfStatus, PreconfStatusResponse, SignableBLS,
    SignedConstraints, SubmitTransactionRequest,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    clients::{
        execution_client::ExecutionClient, relay_client::RelayClient, signer_client::SignerClient,
    },
    error::{PoolError, RpcError},
    network_state::NetworkState,
    preconf_pool::{BlockspaceAvailable, PoolType, PreconfPool, PreconfPoolBuilder},
    pricer::PreconfPricer,
};

#[derive(Clone)]
pub struct PreconfState {
    network_state: NetworkState,
    preconf_pool: Arc<PreconfPool>,
    relay_client: RelayClient,
    signer_client: SignerClient,
}

impl PreconfState {
    pub fn new(
        network_state: NetworkState,
        relay_client: RelayClient,
        signer_client: SignerClient,
        execution_rpc_url: Url,
        taiyi_escrow_address: Address,
    ) -> Self {
        let preconf_pool = PreconfPoolBuilder::new().build(execution_rpc_url, taiyi_escrow_address);
        Self { relay_client, network_state, preconf_pool, signer_client }
    }

    pub fn spawn_constraint_submitter(self) -> impl Future<Output = eyre::Result<()>> {
        let relay_client = self.relay_client.clone();
        let context = self.network_state.context();
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
                    context.get_deadline_of_slot(next_slot).saturating_sub(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs(),
                    );
                tokio::time::sleep(Duration::from_secs(submit_constraint_deadline_duration)).await;
                match self.preconf_pool.ready_requests(next_slot) {
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
                    Err(err) => {
                        debug!(?err, "Error fetching preconf requests for slot");
                        continue;
                    }
                }
            }
            Ok(())
        }
    }

    /// reserve blockspace for a slot
    ///
    /// Requirements for target slot:
    /// 1. Must be at least 2 slots ahead of current slot
    pub async fn reserve_blockspace(
        &self,
        request: BlockspaceAllocation,
        signer: Address,
    ) -> Result<Uuid, RpcError> {
        // Check if the gateway is delegated for the target slot
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

        // Construct a preconf request
        let preconf_request =
            PreconfRequest { allocation: request, transaction: None, signer: Some(signer) };

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
        let signer = match preconf_request.signer() {
            Some(signer) => signer,
            None => return Err(RpcError::UnknownError("No signer found".to_string())),
        };
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

        preconf_request.transaction = Some(request.transaction.clone());

        match self
            .preconf_pool
            .submit_transaction(preconf_request.clone(), request.request_id)
            .await
        {
            Ok(_) => {
                let commitment =
                    self.signer_client.sign_with_ecdsa(request.digest()).await.map_err(|e| {
                        RpcError::SignatureError(format!("Failed to issue commitment: {e:?}"))
                    })?;
                Ok(PreconfResponse::success(request.request_id, Some(commitment)))
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
        let deadline = self.network_state.context().get_deadline_of_slot(slot);
        utc_timestamp > deadline
    }

    pub fn chain_id(&self) -> u64 {
        self.network_state.chain_id()
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct GetSlotResponse {
    pub slot: u64,
    pub blockspace_available: BlockspaceAvailable,
}
