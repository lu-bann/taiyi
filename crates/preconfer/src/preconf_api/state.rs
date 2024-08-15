use std::sync::Arc;

use alloy::{
    consensus::{Transaction, TxEnvelope},
    network::Ethereum,
    providers::Provider,
    rlp::Encodable,
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
    transports::Transport,
};
use cb_pbs::BuilderApiState;
use luban_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, PreconfHash,
    PreconfRequest, PreconfResponse, PreconfStatus, PreconfStatusResponse,
};
use parking_lot::RwLock;
use reth::primitives::U256;
use reth_chainspec::ChainSpec;

use crate::{
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
    chain_spec: Arc<ChainSpec>,
    rpc_url: String,
    preconfer: Preconfer<T, P, F>,
    signer_client: SignerClient,
    pubkeys: Vec<BlsPublicKey>,
    network_state: NetworkState,
    preconf_pool: Arc<RwLock<OrderPool>>,
    priortised_orderpool: Arc<RwLock<PrioritizedOrderPool>>,
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
    P: Provider<T, Ethereum> + Clone,
    F: PreconfPricer + Sync,
{
    pub async fn new(
        chain_spec: Arc<ChainSpec>,
        rpc_url: String,
        preconfer: Preconfer<T, P, F>,
        network_state: NetworkState,
        pubkeys: Vec<BlsPublicKey>,
        signer_client: SignerClient,
    ) -> Self {
        Self {
            chain_spec,
            rpc_url,
            preconfer,
            signer_client,
            pubkeys,
            network_state,
            preconf_pool: Arc::new(RwLock::new(OrderPool::default())),
            priortised_orderpool: Arc::new(RwLock::new(PrioritizedOrderPool::default())),
        }
    }

    pub async fn sign_init_signature(
        &self,
        preconf_request: &PreconfRequest,
    ) -> Result<BlsSignature, String> {
        self.signer_client
            .sign_constraint(
                preconf_request,
                *self.pubkeys.first().expect("tempory solution"),
            )
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
        let preconf_hash = preconf_request.hash(U256::from(self.chain_spec.chain().id()));
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
        let preconf_request: Option<PreconfRequest>;
        {
            preconf_request = self.preconf_pool.read().get(&preconf_tx_hash);
        }
        match preconf_request {
            Some(mut preconf_request) => {
                // TODO: Validate the tx
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
            }
            None => {
                return Err(RpcError::PreconfRequestNotFound(preconf_tx_hash));
            }
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
        if tx.chain_id().expect("no chain id") != self.chain_spec.chain().id() {
            return Err(ValidationError::ChainIdMismatch);
        }

        let transaction_size: usize;
        {
            transaction_size = self.priortised_orderpool.read().transaction_size();
        }
        // Check for max commitment reached for the slot
        if transaction_size > MAX_COMMITMENTS_PER_SLOT {
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
