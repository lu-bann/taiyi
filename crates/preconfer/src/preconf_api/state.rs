use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::{Header, Transaction};
use alloy_eips::{eip1559::BaseFeeParams, eip2718::Encodable2718, BlockId};
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{
    keccak256, private::alloy_rlp::Decodable, Address, Bytes, PrimitiveSignature, U256,
};
use alloy_provider::{ext::DebugApi, utils::EIP1559_MIN_PRIORITY_FEE, Provider};
use ethereum_consensus::{
    clock::from_system_time, deneb::mainnet::MAX_BYTES_PER_TRANSACTION, primitives::BlsPublicKey,
    ssz::prelude::ByteList,
};
use futures::StreamExt;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use taiyi_primitives::{
    BlockspaceAllocation, ConstraintsMessage, PreconfRequest, PreconfRequestTypeA,
    PreconfRequestTypeB, PreconfResponse, SignableBLS, SignedConstraints, SubmitTransactionRequest,
    SubmitTypeATransactionRequest,
};
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::{
    clients::{relay_client::RelayClient, signer_client::SignerClient},
    context_ext::ContextExt,
    contract::{core::TaiyiCore, to_solidity_type},
    error::{PoolError, RpcError},
    network_state::NetworkState,
    preconf_pool::{PreconfPool, PreconfPoolBuilder},
};

#[derive(Clone)]
pub struct PreconfState<P> {
    network_state: NetworkState,
    preconf_pool: Arc<PreconfPool>,
    relay_client: RelayClient,
    signer_client: SignerClient,
    provider: P,
}

impl<P> PreconfState<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    pub fn new(
        network_state: NetworkState,
        relay_client: RelayClient,
        signer_client: SignerClient,
        execution_rpc_url: Url,
        taiyi_escrow_address: Address,
        provider: P,
    ) -> Self {
        let preconf_pool = PreconfPoolBuilder::new().build(execution_rpc_url, taiyi_escrow_address);
        Self { relay_client, network_state, preconf_pool, signer_client, provider }
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

                // calculate base fee for next slot based on parent header
                // Its fine to use latest block as we are submitting constraints for next block
                let rlp_encoded_header =
                    self.provider.debug_get_raw_header(BlockId::latest()).await?;
                let header = Header::decode(&mut rlp_encoded_header.as_ref())?;
                let (base_fee, priority_fee) =
                    match header.next_block_base_fee(BaseFeeParams::ethereum()) {
                        Some(base_fee) => (base_fee.into(), EIP1559_MIN_PRIORITY_FEE),
                        None => {
                            let estimate = self.provider.estimate_eip1559_fees(None).await?;
                            (estimate.max_fee_per_gas, estimate.max_priority_fee_per_gas)
                        }
                    };

                // wait unit the deadline to submit constraints
                tokio::time::sleep(Duration::from_secs(submit_constraint_deadline_duration)).await;

                info!("Current base fee: {base_fee}");

                let signer = self.signer_client.ecdsa_signer();
                let wallet = EthereumWallet::from(signer.clone());
                let sender = self.signer_client.ecdsa_address();

                let taiyi_core =
                    TaiyiCore::new(self.preconf_pool.taiyi_escrow_address, self.provider.clone());

                let mut constraints = Vec::new();
                let mut sponsoring_tx = Vec::new();
                let mut type_a_txs = Vec::new();
                let mut type_b_txs = Vec::new();
                let mut exhaust_txs = Vec::new();

                let mut nonce = self.provider.get_transaction_count(sender).await?;

                // Accounts to sponsor gas for
                let mut accounts = Vec::new();
                // Amounts to sponsor for each account
                let mut amounts = Vec::new();

                match self.preconf_pool.ready_requests(next_slot) {
                    Ok(preconf_requests) => {
                        for preconf_req in preconf_requests {
                            match preconf_req {
                                PreconfRequest::TypeA(request) => {
                                    let tip_tx_gas_uesd = self
                                        .preconf_pool
                                        .calculate_gas_used(request.tip_transaction.clone())
                                        .await?;
                                    let preconf_tx_gas_used = self
                                        .preconf_pool
                                        .calculate_gas_used(request.preconf_tx.clone())
                                        .await?;

                                    accounts
                                        .push(request.signer().expect("Signer must be present"));
                                    amounts.push(U256::from(
                                        (tip_tx_gas_uesd + preconf_tx_gas_used) as u128 * base_fee,
                                    ));

                                    let mut tx_encoded = Vec::new();
                                    request.tip_transaction.encode_2718(&mut tx_encoded);
                                    let tx_ref: &[u8] = tx_encoded.as_ref();
                                    let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                                        tx_ref.try_into().expect("tx bytes too big");
                                    type_a_txs.push(tx_bytes);

                                    let mut tx_encoded = Vec::new();
                                    request.preconf_tx.encode_2718(&mut tx_encoded);
                                    let tx_ref: &[u8] = tx_encoded.as_ref();
                                    let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                                        tx_ref.try_into().expect("tx bytes too big");
                                    type_a_txs.push(tx_bytes);
                                }
                                PreconfRequest::TypeB(preconf_req) => {
                                    if let Some(ref tx) = preconf_req.transaction {
                                        // calculate gas used
                                        let gas_used = self
                                            .preconf_pool
                                            .calculate_gas_used(tx.clone())
                                            .await?;

                                        accounts.push(
                                            preconf_req.signer().expect("Signer must be present"),
                                        );
                                        amounts.push(U256::from(gas_used as u128 * base_fee));

                                        // preconf tx
                                        let mut tx_encoded = Vec::new();
                                        tx.encode_2718(&mut tx_encoded);
                                        let tx_ref: &[u8] = tx_encoded.as_ref();
                                        let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                                            tx_ref.try_into().expect("tx bytes too big");
                                        type_b_txs.push(tx_bytes);

                                        // Append with a transaction that calls get_tip() on TaiyiCore contract
                                        let blockspace_allocation_sig_user = preconf_req.alloc_sig;
                                        let blockspace_allocation_sig_gateway = self
                                            .signer_client
                                            .sign_with_ecdsa(preconf_req.allocation.digest())
                                            .await
                                            .map_err(|e| {
                                                RpcError::SignatureError(format!("{e:?}"))
                                            })?;
                                        let gateway_signed_raw_tx = self
                                            .signer_client
                                            .sign_with_ecdsa(keccak256(tx_encoded.clone()))
                                            .await
                                            .map_err(|e| {
                                                RpcError::SignatureError(format!(
                                                    "Failed to issue commitment: {e:?}"
                                                ))
                                            })?;
                                        let preconf_request_type_b = to_solidity_type(
                                            preconf_req,
                                            blockspace_allocation_sig_user,
                                            blockspace_allocation_sig_gateway,
                                            tx_encoded.into(),
                                            gateway_signed_raw_tx,
                                            self.preconf_pool.taiyi_escrow_address,
                                        );

                                        // Call getTip() on TaiyiCore contract
                                        let get_tip_tx = taiyi_core
                                            .getTip(preconf_request_type_b)
                                            .into_transaction_request()
                                            .with_nonce(nonce)
                                            .with_gas_limit(100_000)
                                            .with_max_fee_per_gas(base_fee)
                                            .with_max_priority_fee_per_gas(priority_fee)
                                            .build(&wallet)
                                            .await?;
                                        // increment nonce
                                        nonce += 1;
                                        let mut tx_encoded = Vec::new();
                                        get_tip_tx.encode_2718(&mut tx_encoded);
                                        let tx_ref: &[u8] = tx_encoded.as_ref();
                                        let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                                            tx_ref.try_into().expect("tx bytes too big");
                                        type_b_txs.push(tx_bytes);
                                    }
                                }
                            }
                        }

                        //  gas sponsorship tx
                        let sponsor_tx = taiyi_core
                            .sponsorEthBatch(accounts, amounts)
                            .into_transaction_request()
                            .with_nonce(nonce)
                            .with_gas_limit(1_000_000)
                            .with_max_fee_per_gas(base_fee)
                            .with_max_priority_fee_per_gas(priority_fee)
                            .build(&wallet)
                            .await?;

                        let mut tx_bytes = Vec::new();
                        sponsor_tx.encode_2718(&mut tx_bytes);
                        let tx_ref: &[u8] = tx_bytes.as_ref();
                        let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                            tx_ref.try_into().expect("tx bytes too big");
                        sponsoring_tx.push(tx_bytes);
                    }
                    Err(err) => {
                        debug!(?err, "Error fetching preconf requests for slot");
                    }
                }

                // Fetch all preconf requests for which the gateway must call exhaust() on TaiyiCore contract
                let requests = self.preconf_pool.fetch_pending(next_slot);
                if let Some(requests) = requests {
                    info!(
                        "Found {} preconf requests for slot {} to be exhausted",
                        requests.len(),
                        next_slot
                    );

                    for preconf_req in requests {
                        let blockspace_allocation_sig_user = preconf_req.alloc_sig;
                        let blockspace_allocation_sig_gateway = self
                            .signer_client
                            .sign_with_ecdsa(preconf_req.allocation.digest())
                            .await
                            .map_err(|e| {
                                RpcError::SignatureError(format!(
                                    "Failed to issue commitment: {e:?}"
                                ))
                            })?;
                        let preconf_request_type_b = to_solidity_type(
                            preconf_req,
                            blockspace_allocation_sig_user,
                            blockspace_allocation_sig_gateway,
                            Bytes::default(),
                            self.signer_client
                                .sign_with_ecdsa(keccak256(Bytes::default()))
                                .await
                                .map_err(|e| {
                                RpcError::SignatureError(format!(
                                    "Failed to issue commitment: {e:?}"
                                ))
                            })?,
                            self.preconf_pool.taiyi_escrow_address,
                        );

                        // Call exhaust() on TaiyiCore contract
                        let exhaust_tx = taiyi_core
                            .exhaust(preconf_request_type_b)
                            .into_transaction_request()
                            .with_nonce(nonce)
                            .with_gas_limit(1_000_000)
                            .with_max_fee_per_gas(base_fee)
                            .with_max_priority_fee_per_gas(priority_fee)
                            .build(&wallet)
                            .await?;
                        // increment nonce
                        nonce += 1;

                        let mut tx_encoded = Vec::new();
                        exhaust_tx.encode_2718(&mut tx_encoded);
                        let tx_ref: &[u8] = tx_encoded.as_ref();
                        let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                            tx_ref.try_into().expect("tx bytes too big");
                        exhaust_txs.push(tx_bytes);
                    }
                }

                constraints.extend(sponsoring_tx);
                constraints.extend(type_a_txs);
                constraints.extend(type_b_txs);
                constraints.extend(exhaust_txs);

                let txs_len = constraints.len();
                if txs_len != 0 {
                    let bls_pk = self.signer_client.bls_pubkey();
                    let message = ConstraintsMessage {
                        pubkey: BlsPublicKey::try_from(bls_pk.to_bytes().as_ref())
                            .expect("key error"),
                        slot: next_slot,
                        top: false,
                        transactions: constraints.try_into().expect("tx too big"),
                    };
                    let digest = message.digest();
                    if let Ok(signature) = self.signer_client.sign_with_bls(context.clone(), digest)
                    {
                        let signed_constraints_message =
                            vec![SignedConstraints { message, signature }];

                        let max_retries = 5;
                        let mut i = 0;

                        info!("Submitting {txs_len} constraints to relay on  slot {next_slot}");
                        'submit: while let Err(e) =
                            relay_client.set_constraints(signed_constraints_message.clone()).await
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

        // Construct a preconf request
        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig,
            transaction: None,
            signer: Some(signer),
        };

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
            .validate_and_store(
                taiyi_primitives::PreconfRequest::TypeB(preconf_request.clone()),
                request.request_id,
            )
            .await
        {
            Ok(result) => {
                let commitment =
                    self.signer_client.sign_with_ecdsa(result.digest()).await.map_err(|e| {
                        RpcError::SignatureError(format!("Failed to issue commitment: {e:?}"))
                    })?;
                Ok(PreconfResponse::success(request.request_id, Some(commitment)))
            }
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn submit_typea_transaction(
        &self,
        request: SubmitTypeATransactionRequest,
        signature: PrimitiveSignature,
    ) -> Result<PreconfResponse, RpcError> {
        let signer = signature
            .recover_address_from_prehash(&request.digest())
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;

        // Check deadline
        let request_id = Uuid::new_v4();
        let preconf_request = PreconfRequestTypeA {
            preconf_tx: request.clone().preconf_tx,
            tip_transaction: request.clone().tip_transaction,
            target_slot: request.target_slot,
            sequence_number: None,
            signer: Some(signer),
        };

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
                    self.signer_client.sign_with_ecdsa(result.digest()).await.map_err(|e| {
                        RpcError::SignatureError(format!("Failed to issue commitment: {e:?}"))
                    })?;
                Ok(PreconfResponse::success(request_id, Some(commitment)))
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
            .filter(|slot| *slot > current_slot + slot_diff)
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

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SlotInfo {
    pub slot: u64,
    pub gas_available: u64,
    pub blobs_available: usize,
    pub constraints_available: u32,
}
