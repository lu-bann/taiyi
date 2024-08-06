use std::sync::Arc;

use alloy::{
    consensus::TxEnvelope,
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
    signer_client::SignerClient,
    validation::validate_tx_request,
};

#[derive(Clone)]
pub struct PreconfState<T, P, F> {
    chain_spec: Arc<ChainSpec>,
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
        preconfer: Preconfer<T, P, F>,
        network_state: NetworkState,
        pubkeys: Vec<BlsPublicKey>,
        signer_client: SignerClient,
    ) -> Self {
        Self {
            chain_spec,
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
        match self.preconf_pool.read().get(&preconf_tx_hash) {
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
                if validate_tx_request(
                    &self.chain_spec,
                    &preconf_tx,
                    &preconf_request,
                    &mut self.priortised_orderpool.write(),
                )
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
}
