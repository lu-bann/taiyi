use alloy::{
    primitives::U256,
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use cb_common::commit::{
    client::SignerClient as CBSignerClient, error::SignerClientError, request::SignRequest,
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

    pub async fn get_pubkeys(&self) -> Result<Vec<BlsPublicKey>, SignerClientError> {
        Ok(self.cb_signer_client.get_pubkeys().await?.consensus)
    }

    pub async fn sign_constraint(
        &self,
        preconf_request: &PreconfRequest,
        pubkey: BlsPublicKey,
    ) -> Result<BlsSignature, SignerClientError> {
        let root = preconf_request.hash(self.chain_id);
        let proxy_delegation = self.cb_signer_client.generate_proxy_key(pubkey).await?;
        let proxy_pubkey = proxy_delegation.message.proxy;
        let request = SignRequest::new(proxy_pubkey, false, root.into());
        self.cb_signer_client.request_signature(&request).await
    }
}
