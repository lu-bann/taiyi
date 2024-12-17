// the code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/client/engine.rs
use std::ops::Deref;

use alloy_network::AnyNetwork;
use alloy_primitives::Bytes;
use alloy_provider::{ext::EngineApi, RootProvider};
use alloy_rpc_client::RpcClient;
use alloy_rpc_types_engine::{ClientCode, ClientVersionV1, JwtSecret};
use alloy_transport::TransportResult;
use alloy_transport_http::{
    hyper_util::{
        client::legacy::{connect::HttpConnector, Client},
        rt::TokioExecutor,
    },
    AuthLayer, AuthService, Http, HyperClient,
};
use http_body_util::Full;
use lazy_static::lazy_static;
use reqwest::Url;
use tower::ServiceBuilder;

/// A Hyper HTTP client with a JWT authentication layer.
type HyperAuthClient<B = Full<Bytes>> = HyperClient<B, AuthService<Client<HttpConnector, B>>>;

/// The [`EngineClient`] is responsible for interacting with the engine API via HTTP.
/// The inner transport uses a JWT [AuthLayer] to authenticate requests.
#[derive(Debug, Clone)]
pub struct EngineClient {
    inner: RootProvider<Http<HyperAuthClient>, AnyNetwork>,
}

impl Deref for EngineClient {
    type Target = RootProvider<Http<HyperAuthClient>, AnyNetwork>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl EngineClient {
    /// Creates a new [`EngineClient`] from the provided [Url] and [JwtSecret].
    pub fn new_http(url: Url, jwt: JwtSecret) -> Self {
        let hyper_client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

        let auth_layer = AuthLayer::new(jwt);
        let service = ServiceBuilder::new().layer(auth_layer).service(hyper_client);

        let layer_transport = HyperClient::with_service(service);
        let http_hyper = Http::with_client(layer_transport, url);
        let rpc_client = RpcClient::new(http_hyper, true);
        let inner = RootProvider::<_, AnyNetwork>::new(rpc_client);

        Self { inner }
    }

    /// Send a request to identify the engine client version.
    pub async fn engine_client_version(&self) -> TransportResult<Vec<ClientVersionV1>> {
        self.inner.get_client_version_v1(MOCKED_ENGINE_VERSION.clone()).await
    }
}

lazy_static! {
    /// The mocked engine version for the Bolt sidecar.
    pub static ref MOCKED_ENGINE_VERSION: ClientVersionV1 = ClientVersionV1 {
        code: ClientCode::RH, // pretend we are Reth
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        name: "TaiyiBoost".to_string(),
        commit: "main".to_string(),
    };
}
