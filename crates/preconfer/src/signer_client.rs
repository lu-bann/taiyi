use alloy_primitives::U256;
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::commit::{
    client::{GetPubkeysResponse, SignerClient as CBSignerClient},
    error::SignerClientError,
    request::SignRequest,
};
use luban_primitives::PreconfRequest;

#[derive(Debug, Clone)]
pub struct SignerClient {
    cb_signer_client: CBSignerClient,
    _url: String,
    chain_id: U256,
    _cb_id: String,
    _cb_jwt: String,
}

impl SignerClient {
    pub fn new(url: String, chain_id: U256, cb_id: String, cb_jwt: String) -> Self {
        Self {
            cb_signer_client: CBSignerClient::new(url.clone(), &cb_jwt)
                .expect("commit boost signer module"),
            _url: url,
            chain_id,
            _cb_id: cb_id,
            _cb_jwt: cb_jwt,
        }
    }

    pub async fn get_pubkeys(&self) -> Result<GetPubkeysResponse, SignerClientError> {
        self.cb_signer_client.get_pubkeys().await
    }

    pub fn cb_signer_client(&self) -> &CBSignerClient {
        &self.cb_signer_client
    }

    pub async fn sign_constraint(
        &self,
        preconf_request: &PreconfRequest,
        pubkey: BlsPublicKey,
    ) -> Result<BlsSignature, SignerClientError> {
        let root = preconf_request.hash(self.chain_id);
        let request = SignRequest::new(pubkey, false, root.into());
        self.cb_signer_client.request_signature(&request).await
    }
}
