use alloy_consensus::{Transaction, TxEnvelope};
use alloy_network::Ethereum;
use alloy_primitives::U256;
use alloy_provider::Provider;
use alloy_rlp::Encodable;
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use alloy_transport::Transport;
use cb_pbs::BuilderApiState;
use ethereum_consensus::crypto::Signature;
use ethereum_consensus::{
    builder::compute_builder_domain,
    deneb::{compute_signing_root, Context},
};
use luban_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage,
    PreconfHash, PreconfRequest, PreconfResponse, PreconfStatus, PreconfStatusResponse,
    SignedConstraintsMessage,
};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

use crate::{
    constraint_client::ConstraintClient,
    error::RpcError,
    network_state::NetworkState,
    orderpool::{orderpool::OrderPool, priortised_orderpool::PrioritizedOrderPool},
    preconfer::{Preconfer, TipTx},
    pricer::PreconfPricer,
    rpc_state::{get_account_state, AccountState},
    signer_client::SignerClient,
    validation::ValidationError,
};

pub(crate) const MAX_COMMITMENTS_PER_SLOT: usize = 1024 * 1024;

#[derive(Clone)]
pub struct PreconfState<T, P, F> {
    chainid: u64,
    proxy_key_map: HashMap<BlsPublicKey, BlsPublicKey>,
    rpc_url: String,
    preconfer: Preconfer<T, P, F>,
    signer_client: SignerClient,
    constraint_client: ConstraintClient,
    network_state: NetworkState,
    preconf_pool: Arc<RwLock<OrderPool>>,
    priortised_orderpool: Arc<RwLock<PrioritizedOrderPool>>,
    context: Context,
}

impl<
        T: Clone + Send + Sync + 'static,
        P: Clone + Send + Sync + 'static,
        F: Clone + Send + Sync + 'static,
    > BuilderApiState for PreconfState<T, P, F>
{
}

impl<T, P, F> PreconfState<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone + 'static,
    F: PreconfPricer + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        chainid: u64,
        proxy_key_map: HashMap<BlsPublicKey, BlsPublicKey>,
        rpc_url: String,
        preconfer: Preconfer<T, P, F>,
        network_state: NetworkState,
        signer_client: SignerClient,
        constraint_client: ConstraintClient,
        context: Context,
    ) -> Self {
        Self {
            chainid,
            proxy_key_map,
            rpc_url,
            preconfer,
            signer_client,
            constraint_client,
            network_state,
            preconf_pool: Arc::new(RwLock::new(OrderPool::default())),
            priortised_orderpool: Arc::new(RwLock::new(PrioritizedOrderPool::default())),
            context,
        }
    }

    fn key_for_slot(&self, slot: u64) -> BlsPublicKey {
        self.network_state
            .propser_duty_for_slot(slot)
            .expect("Proposer duty should exist")
            .pubkey
    }

    pub fn constraints(&self) -> ConstraintsMessage {
        self.priortised_orderpool.write().constraints()
    }

    async fn signed_constraints_message(&self) -> Result<SignedConstraintsMessage, String> {
        let domain = compute_builder_domain(&self.context).map_err(|e| e.to_string())?;
        let constraints_message = self.constraints();
        let signing_root =
            compute_signing_root(&constraints_message, domain).map_err(|e| e.to_string())?;
        let consensus_key = self.key_for_slot(constraints_message.slot);
        let proxy_key = self
            .proxy_key_map
            .get(&consensus_key)
            .expect("proxy key should exist");
        let signature = self
            .signer_client
            .sign_message(signing_root.into(), *proxy_key)
            .await
            .map_err(|e| e.to_string())?;
        let signature = Signature::try_from(signature.as_ref()).map_err(|e| e.to_string())?;
        Ok(SignedConstraintsMessage::new(
            constraints_message,
            signature,
        ))
    }

    pub async fn spawn_constraint_submitter(self) {
        let constraint_client = self.constraint_client.clone();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(7));
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                let signed_constraints_message = self
                    .signed_constraints_message()
                    .await
                    .expect("signed constraints");
                if let Err(e) = constraint_client
                    .send_set_constraints(signed_constraints_message)
                    .await
                {
                    eprintln!("Error in sending constraints: {e:?}");
                }
            }
        });
    }

    pub async fn sign_init_signature(
        &self,
        preconf_request: &PreconfRequest,
    ) -> Result<BlsSignature, String> {
        let consensus_key = self.key_for_slot(preconf_request.preconf_conditions.slot);
        let proxy_key = self
            .proxy_key_map
            .get(&consensus_key)
            .expect("proxy key should exist");
        self.signer_client
            .sign_preconf_request(preconf_request, *proxy_key)
            .await
            .map_err(|e| e.to_string())
    }

    /// Send a preconf request to the preconfer
    ///
    /// Stores the preconf request in the Orderpool until the preconf tx is received
    pub async fn send_preconf_request(
        &self,
        mut preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        let preconf_hash = preconf_request.hash(U256::from(self.chainid));
        if self.preconf_pool.read().exist(&preconf_hash) {
            return Err(RpcError::PreconfRequestAlreadyExist(preconf_hash));
        }
        let preconfer_signature = self
            .sign_init_signature(&preconf_request)
            .await
            .map_err(RpcError::UnknownError)?;

        let _block_number = preconf_request.preconf_conditions.block_number;
        preconf_request.init_signature = preconfer_signature;
        match self
            .preconfer
            .verify_escrow_balance_and_calc_fee(&preconf_request.tip_tx.from, &preconf_request)
            .await
        {
            Ok(res) => {
                if !res {
                    return Err(RpcError::PreconfTxNotValid(
                        "preconf request not valid".to_string(),
                    ));
                }
            }
            Err(e) => return Err(RpcError::UnknownError(format!("validate error {e:?}"))),
        }

        self.preconf_pool
            .write()
            .set(preconf_hash, preconf_request.clone());

        Ok(PreconfResponse::success(preconf_hash, preconfer_signature))
    }

    pub async fn cancel_preconf_request(
        &self,
        cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, RpcError> {
        if self
            .preconf_pool
            .write()
            .delete(&cancel_preconf_request.preconf_hash)
            .is_some()
        {
            Ok(CancelPreconfResponse {})
        } else {
            Err(RpcError::PreconfRequestNotFound(
                cancel_preconf_request.preconf_hash,
            ))
        }
    }

    pub async fn send_preconf_tx_request(
        &self,
        preconf_tx_hash: PreconfHash,
        preconf_tx: TxEnvelope,
    ) -> Result<(), RpcError> {
        let mut preconf_request = self
            .preconf_pool
            .read()
            .get(&preconf_tx_hash)
            .ok_or(RpcError::PreconfRequestNotFound(preconf_tx_hash))?;

        // User is expected to send the tx calldata in the same slot specified in the preconf request.
        let target_slot = preconf_request.preconf_conditions.slot;
        if target_slot != self.priortised_orderpool.read().slot.expect("slot") {
            return Err(RpcError::PreconfTxNotValid(
                "preconf tx not valid".to_string(),
            ));
        }

        if preconf_request.preconf_tx.is_some() {
            return Err(RpcError::PreconfTxAlreadySet(preconf_tx_hash));
        }
        let mut tx = Vec::new();
        preconf_tx.encode(&mut tx);
        preconf_request.preconf_tx = Some(tx);

        self.preconf_pool
            .write()
            .set(preconf_tx_hash, preconf_request.clone());

        // Call exhuast if validate_tx_request fails
        if self
            .validate_tx_request(&preconf_tx, &preconf_request)
            .await
            .is_err()
        {
            self.preconfer
                .luban_core_contract
                .exhaust(
                    TipTx {
                        gasLimit: preconf_request.tip_tx.gas_limit,
                        from: preconf_request.tip_tx.from,
                        to: preconf_request.tip_tx.to,
                        prePay: preconf_request.tip_tx.pre_pay,
                        afterPay: preconf_request.tip_tx.after_pay,
                        nonce: preconf_request.tip_tx.nonce,
                    },
                    preconf_request.init_signature.into(),
                    preconf_request.preconfer_signature,
                )
                .call()
                .await?;
        } else {
            self.priortised_orderpool
                .write()
                .insert_order(preconf_tx_hash, preconf_request);
            self.preconf_pool.write().delete(&preconf_tx_hash);
        }

        Ok(())
    }

    // TODO: change this
    pub async fn check_preconf_request_status(
        &self,
        preconf_tx_hash: PreconfHash,
    ) -> Result<PreconfStatusResponse, RpcError> {
        match self.preconf_pool.read().get(&preconf_tx_hash) {
            Some(preconf_request) => Ok(PreconfStatusResponse {
                status: PreconfStatus::Accepted,
                data: preconf_request,
            }),
            None => Err(RpcError::PreconfRequestNotFound(preconf_tx_hash)),
        }
    }
    pub async fn available_slot(&self) -> Result<AvailableSlotResponse, RpcError> {
        Ok(AvailableSlotResponse {
            current_slot: self.network_state.get_current_slot(),
            current_epoch: self.network_state.get_current_epoch(),
            available_slots: self.network_state.get_proposer_duties(),
        })
    }

    // TDOD: validate all fields
    // After validating the tx req, update the state in insert_order function
    async fn validate_tx_request(
        &self,
        tx: &TxEnvelope,
        order: &PreconfRequest,
    ) -> Result<(), ValidationError> {
        let sender = order.tip_tx.from;
        // Vaiidate the chain id
        if tx.chain_id().expect("no chain id") != self.chainid {
            return Err(ValidationError::ChainIdMismatch);
        }

        let pool_size: usize;
        {
            pool_size = self.priortised_orderpool.read().pool_size();
        }
        // Check for max commitment reached for the slot
        if pool_size > MAX_COMMITMENTS_PER_SLOT {
            return Err(ValidationError::MaxCommitmentsReachedForSlot(
                order.preconf_conditions.block_number,
                MAX_COMMITMENTS_PER_SLOT,
            ));
        }

        // TODO
        // Check for max committed gas reached for the slot
        // Check if the transaction size exceeds the maximum
        // Check if the transaction is a contract creation and the init code size exceeds the maximum
        // Check if the gas limit is higher than the maximum block gas limit
        // Check EIP-4844-specific limits

        let gas_limit = get_tx_gas_limit(tx);
        if U256::from(gas_limit) > order.tip_tx.gas_limit {
            return Err(ValidationError::GasLimitTooHigh);
        }

        let (prev_balance, prev_nonce) = self
            .priortised_orderpool
            .read()
            .intermediate_state
            .get(&sender)
            .cloned()
            .unwrap_or_default();

        let account_state_opt: Option<AccountState>;
        {
            account_state_opt = self
                .priortised_orderpool
                .read()
                .canonical_state
                .get(&sender)
                .copied();
        }

        let mut account_state = match account_state_opt {
            Some(state) => state,
            None => {
                let state = get_account_state(self.rpc_url.clone(), sender)
                    .await
                    .map_err(|e| {
                        ValidationError::Internal(format!("Failed to get account state: {e:?}"))
                    })?;
                {
                    self.priortised_orderpool
                        .write()
                        .canonical_state
                        .insert(sender, state);
                }
                state
            }
        };
        // apply the nonce and balance diff
        account_state.nonce += prev_nonce;
        account_state.balance -= prev_balance;

        let nonce = order.nonce();

        // order can't be included
        if account_state.nonce > nonce.to() {
            return Err(ValidationError::NonceTooLow(
                account_state.nonce,
                nonce.to(),
            ));
        }

        if account_state.nonce < nonce.to() {
            return Err(ValidationError::NonceTooHigh(
                account_state.nonce,
                nonce.to(),
            ));
        }
        Ok(())
    }
}

fn get_tx_gas_limit(tx: &TxEnvelope) -> u128 {
    match tx {
        TxEnvelope::Legacy(t) => t.tx().gas_limit,
        TxEnvelope::Eip2930(t) => t.tx().gas_limit,
        TxEnvelope::Eip1559(t) => t.tx().gas_limit,
        TxEnvelope::Eip4844(t) => t.tx().tx().gas_limit,
        _ => panic!("not implemted"),
    }
}
