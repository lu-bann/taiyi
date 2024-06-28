use crate::base_fee_fetcher::{BaseFeeFetcher, ExecutionClientFeeFetcher, LubanFeeFetcher};
use crate::commit_boost_client::CommitBoostClient;
use crate::error::RpcError;
use crate::preconf_request_map::PreconfRequestMap;
use crate::validator::Validator;
use alloy_consensus::TxEnvelope;
use alloy_core::primitives::{Address, U256};
use alloy_provider::ProviderBuilder;
use alloy_provider::{network::Ethereum, Provider};
use alloy_rlp::Encodable;
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use alloy_transport::Transport;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use luban_primitives::{
    CancelPreconfRequest, CancelPreconfResponse, PreconfHash, PreconfRequest, PreconfResponse,
    PreconfStatus, PreconfStatusResponse,
};
use tracing::info;

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
}

pub struct LubanRpcImpl<T, P, F> {
    chain_id: U256,
    preconf_requests: PreconfRequestMap,
    validator: Validator<T, P, F>,
    commit_boost_client: CommitBoostClient,
    pubkeys: Vec<BlsPublicKey>,
}

impl<T, P, F> LubanRpcImpl<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum>,
    F: BaseFeeFetcher,
{
    pub async fn new(
        chain_id: U256,
        validator: Validator<T, P, F>,
        commit_boost_url: String,
    ) -> Self {
        let commit_boost_client = CommitBoostClient::new(commit_boost_url, chain_id);
        let pubkeys = commit_boost_client
            .get_pubkeys()
            .await
            .expect("pubkeys should be received.");
        Self {
            chain_id,
            preconf_requests: PreconfRequestMap::default(),
            validator,
            commit_boost_client,
            pubkeys,
        }
    }
    async fn sign_init_signature(
        &self,
        preconf_request: &PreconfRequest,
    ) -> Result<BlsSignature, String> {
        self.commit_boost_client
            .sign_constraint(
                preconf_request,
                *self.pubkeys.first().expect("tempory solution"),
            )
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl<T, P, F> LubanRpcServer for LubanRpcImpl<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone + 'static,
    F: BaseFeeFetcher + Sync + Send + 'static,
{
    async fn send_preconf_request(
        &self,
        mut preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        let preconf_hash = preconf_request.hash(self.chain_id);
        if self.preconf_requests.exist(&preconf_hash) {
            return Err(RpcError::PreconfRequestAlreadyExist(preconf_hash));
        }
        let preconfer_signature = self
            .sign_init_signature(&preconf_request)
            .await
            .map_err(RpcError::UnknownError)?;
        preconf_request.init_signature = preconfer_signature;
        match self
            .validator
            .validate(&preconf_request.tip_tx.from, &preconf_request)
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
        self.preconf_requests.set(preconf_hash, preconf_request);

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
        match self.preconf_requests.get(&preconf_tx_hash) {
            Some(mut preconf_request) => {
                if preconf_request.preconf_tx.is_some() {
                    return Err(RpcError::PreconfTxAlreadySet(preconf_tx_hash));
                }
                let mut tx = Vec::new();
                preconf_tx.encode(&mut tx);
                preconf_request.preconf_tx = Some(tx);
                self.preconf_requests.set(preconf_tx_hash, preconf_request);
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
}

pub async fn start_rpc_server(
    addr: std::net::IpAddr,
    port: u16,
    luban_escrow_contract_addr: Address,
    rpc_url: String,
    luban_service_url: Option<String>,
    commit_boost_url: String,
) -> eyre::Result<()> {
    let server = Server::builder().build((addr, port)).await?;
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_builtin(&rpc_url)
        .await?;
    let chain_id = provider.get_chain_id().await?;
    info!("preconfer is on chain_id: {:?}", chain_id);
    match luban_service_url {
        Some(url) => {
            let base_fee_fetcher = LubanFeeFetcher::new(url);
            let validator = Validator::new(provider, luban_escrow_contract_addr, base_fee_fetcher);
            let rpc = LubanRpcImpl::new(U256::from(chain_id), validator, commit_boost_url).await;
            let handle = server.start(rpc.into_rpc());
            handle.stopped().await;
        }
        None => {
            let base_fee_fetcher = ExecutionClientFeeFetcher::new(provider.clone());
            let validator = Validator::new(provider, luban_escrow_contract_addr, base_fee_fetcher);
            let rpc = LubanRpcImpl::new(U256::from(chain_id), validator, commit_boost_url).await;
            let handle = server.start(rpc.into_rpc());
            handle.stopped().await;
        }
    };

    Ok(())
}
