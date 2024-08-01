use crate::error::RpcError;
use crate::lookahead_fetcher;
use crate::network_state::NetworkState;
use crate::orderpool::orderpool::OrderPool;
use crate::preconf_request_map::PreconfRequestMap;
use crate::preconfer::{Preconfer, TipTx};
use crate::pricer::{ExecutionClientFeePricer, LubanFeePricer, PreconfPricer};
use crate::signer_client::SignerClient;
use alloy::consensus::TxEnvelope;
use alloy::core::primitives::{Address, U256};
use alloy::network::Ethereum;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rlp::Encodable;
use alloy::rpc::types::beacon::BlsPublicKey;
use alloy::rpc::types::beacon::BlsSignature;
use alloy::transports::Transport;
use eyre::Result;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use luban_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, PreconfHash,
    PreconfRequest, PreconfResponse, PreconfStatus, PreconfStatusResponse, TipTransaction,
};
use tracing::info;

impl From<TipTransaction> for TipTx {
    fn from(tx: TipTransaction) -> Self {
        TipTx {
            gasLimit: tx.gas_limit,
            from: tx.from,
            to: tx.to,
            prePay: tx.pre_pay,
            afterPay: tx.after_pay,
            nonce: tx.nonce,
        }
    }
}

#[rpc(server, client, namespace = "luban")]
pub trait LubanRpc {
    #[method(name = "sendPreconfRequest")]
    async fn send_preconf_request(
        &self,
        preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError>;

    #[method(name = "cancelPreconfRequest")]
    async fn cancel_preconf_request(
        &self,
        cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, RpcError>;

    #[method(name = "sendPreconfTxRequest")]
    async fn send_preconf_tx_request(
        &self,
        preconf_tx_hash: PreconfHash,
        preconf_tx: TxEnvelope,
    ) -> Result<(), RpcError>;

    #[method(name = "checkPreconfRequestStatus")]
    async fn check_preconf_request_status(
        &self,
        preconf_tx_hash: PreconfHash,
    ) -> Result<PreconfStatusResponse, RpcError>;

    #[method(name = "availableSlot")]
    async fn available_slot(&self) -> Result<AvailableSlotResponse, RpcError>;
}

pub struct LubanRpcImpl<T, P, F> {
    chain_id: U256,
    preconf_requests: PreconfRequestMap,
    preconfer: Preconfer<T, P, F>,
    signer_client: SignerClient,
    pubkeys: Vec<BlsPublicKey>,
    network_state: NetworkState,
    preconf_pool: OrderPool,
}

impl<T, P, F> LubanRpcImpl<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum>,
    F: PreconfPricer,
{
    pub async fn new(
        chain_id: U256,
        preconfer: Preconfer<T, P, F>,
        network_state: NetworkState,
        pubkeys: Vec<BlsPublicKey>,
        signer_client: SignerClient,
    ) -> Self {
        Self {
            chain_id,
            preconf_requests: PreconfRequestMap::default(),
            preconfer,
            signer_client,
            pubkeys,
            network_state,
            preconf_pool: OrderPool::default(),
        }
    }
    async fn sign_init_signature(
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

#[async_trait]
impl<T, P, F> LubanRpcServer for LubanRpcImpl<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone + Provider + 'static,
    F: PreconfPricer + Sync + Send + 'static,
{   
    /// Send a preconf request to the preconfer
    /// 
    /// Stores the preconf request in the Orderpool until the preconf tx is received
    async fn send_preconf_request(
        &self,
        mut preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        let preconf_hash = preconf_request.hash(self.chain_id);
        if self.preconf_pool.exist(&preconf_hash) {
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

        self.preconf_pool.set(preconf_hash, preconf_request.clone());

        Ok(PreconfResponse::success(preconf_hash, preconfer_signature))
    }

    async fn cancel_preconf_request(
        &self,
        cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, RpcError> {
        if self
            .preconf_requests
            .delete(&cancel_preconf_request.preconf_hash)
            .is_some()
        {
            return Ok(CancelPreconfResponse {});
        } else {
            return Err(RpcError::PreconfRequestNotFound(
                cancel_preconf_request.preconf_hash,
            ));
        }
    }

    async fn send_preconf_tx_request(
        &self,
        preconf_tx_hash: PreconfHash,
        preconf_tx: TxEnvelope,
    ) -> Result<(), RpcError> {
        match self.preconf_pool.get(&preconf_tx_hash) {
            Some(mut preconf_request) => {
                // TODO: Validate the tx
                if preconf_request.preconf_tx.is_some() {
                    return Err(RpcError::PreconfTxAlreadySet(preconf_tx_hash));
                }
                let mut tx = Vec::new();
                preconf_tx.encode(&mut tx);
                preconf_request.preconf_tx = Some(tx);
                // TODO remove the preconf_request from the pool and move to priortised orderpool
                self.preconf_requests
                    .set(preconf_tx_hash, preconf_request.clone());

                // Call exhuast if
                // - validate_tx fails
                // TODO: move gasLimit check to validate_tx
                let gas_limit = get_tx_gas_limit(&preconf_tx);
                if U256::from(gas_limit) > preconf_request.tip_tx.gas_limit {
                    self.preconfer
                        .luban_core_contract
                        .exhaust(
                            preconf_request.tip_tx.into(),
                            preconf_request.init_signature.into(),
                            preconf_request.preconfer_signature,
                        )
                        .call()
                        .await?;
                }
            }
            None => {
                return Err(RpcError::PreconfRequestNotFound(preconf_tx_hash));
            }
        }

        Ok(())
    }

    async fn check_preconf_request_status(
        &self,
        preconf_tx_hash: PreconfHash,
    ) -> Result<PreconfStatusResponse, RpcError> {
        match self.preconf_requests.get(&preconf_tx_hash) {
            Some(preconf_request) => Ok(PreconfStatusResponse {
                status: PreconfStatus::Accepted,
                data: preconf_request,
            }),
            None => {
                return Err(RpcError::PreconfRequestNotFound(preconf_tx_hash));
            }
        }
    }

    async fn available_slot(&self) -> Result<AvailableSlotResponse, RpcError> {
        Ok(AvailableSlotResponse {
            current_slot: self.network_state.get_current_slot(),
            current_epoch: self.network_state.get_current_epoch(),
            available_slots: self.network_state.get_proposer_duties(),
        })
    }
}

async fn run_cl_process<T, P>(
    provider: P,
    beacon_url: String,
    luban_proposer_registry_contract_addr: Address,
    network_state: NetworkState,
    pubkeys: Vec<BlsPublicKey>,
) -> eyre::Result<()>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    let mut lookahead_fetcher = lookahead_fetcher::LookaheadFetcher::new(
        provider,
        beacon_url,
        luban_proposer_registry_contract_addr,
        network_state,
        pubkeys,
    );
    lookahead_fetcher.initialze().await?;
    lookahead_fetcher.run().await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    addr: std::net::IpAddr,
    port: u16,
    luban_escrow_contract_addr: Address,
    luban_core_contract_addr: Address,
    luban_proposer_registry_contract_addr: Address,
    rpc_url: String,
    beacon_rpc_url: String,
    luban_service_url: Option<String>,
    commit_boost_url: String,
    cb_id: String,
    cb_jwt: String,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_builtin(&rpc_url)
        .await?;
    let chain_id = provider.get_chain_id().await?;

    let provider_cl = provider.clone();
    let network_state = NetworkState::new(0, 0, Vec::new());
    let network_state_cl = network_state.clone();

    let signer_client = SignerClient::new(commit_boost_url, U256::from(chain_id), cb_id, cb_jwt);
    let pubkeys = signer_client
        .get_pubkeys()
        .await
        .expect("pubkeys should be received.");
    let pubkeys_dup = pubkeys.clone();

    tokio::spawn(async move {
        if let Err(e) = run_cl_process(
            provider_cl,
            beacon_rpc_url,
            luban_proposer_registry_contract_addr,
            network_state_cl,
            pubkeys_dup,
        )
        .await
        {
            eprintln!("Error in cl process: {e:?}");
        }
    });

    let server = Server::builder().build((addr, port)).await?;

    info!("preconfer is on chain_id: {:?}", chain_id);
    match luban_service_url {
        Some(url) => {
            let base_fee_fetcher = LubanFeePricer::new(url);
            let validator = Preconfer::new(
                provider,
                luban_escrow_contract_addr,
                luban_core_contract_addr,
                base_fee_fetcher,
            );
            let rpc = LubanRpcImpl::new(
                U256::from(chain_id),
                validator,
                network_state,
                pubkeys,
                signer_client,
            )
            .await;
            let handle = server.start(rpc.into_rpc());
            handle.stopped().await;
        }
        None => {
            let base_fee_fetcher = ExecutionClientFeePricer::new(provider.clone());
            let validator = Preconfer::new(
                provider,
                luban_escrow_contract_addr,
                luban_core_contract_addr,
                base_fee_fetcher,
            );
            let rpc = LubanRpcImpl::new(
                U256::from(chain_id),
                validator,
                network_state,
                pubkeys,
                signer_client,
            )
            .await;
            let handle = server.start(rpc.into_rpc());
            handle.stopped().await;
        }
    };

    Ok(())
}
