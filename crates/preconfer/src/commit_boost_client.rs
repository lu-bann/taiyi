use alloy_core::primitives::U256;
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::commit::{
    client::GetPubkeysResponse,
    constants::{GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
    request::SignRequest,
};
use jsonrpsee::tracing::debug;
use luban_primitives::PreconfRequest;
use tracing::{error, info};

const ID: &str = "luban";

#[derive(Debug)]
pub struct CommitBoostClient {
    url: String,
    chain_id: U256,
    client: reqwest::Client,
}

impl CommitBoostClient {
    pub fn new(url: String, chain_id: U256) -> Self {
        Self {
            url,
            chain_id,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_pubkeys(&self) -> eyre::Result<Vec<BlsPublicKey>> {
        let url = format!("{}{GET_PUBKEYS_PATH}", self.url);

        info!(url, "Loading signatures from commit_boost");

        let response = match self.client.get(url).send().await {
            Ok(res) => res,
            Err(e) => {
                error!(err = ?e, "failed to get public keys from commit-boost, retrying...");
                return Err(eyre::eyre!("failed to get public keys from commit-boost"));
            }
        };

        let status = response.status();
        let response_bytes = response.bytes().await.expect("failed to get bytes");

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            error!(err, ?status, "failed to get public keys, retrying...");
            return Err(eyre::eyre!("failed to get public keys"));
        }

        let pubkeys: GetPubkeysResponse =
            serde_json::from_slice(&response_bytes).expect("failed deser");
        Ok(pubkeys.consensus)
    }

    pub async fn sign_constraint(
        &self,
        preconf_request: &PreconfRequest,
        pubkey: BlsPublicKey,
    ) -> eyre::Result<BlsSignature> {
        let root = preconf_request.hash(self.chain_id);
        let request = SignRequest::new(ID, pubkey, false, root.into());

        let url = format!("{}{REQUEST_SIGNATURE_PATH}", self.url);

        debug!(url, ?request, "Requesting signature from commit_boost");

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let response_bytes = response.bytes().await?;

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            tracing::error!(err, "failed to get signature");
            return Err(eyre::eyre!("failed to get signature"));
        }

        Ok(serde_json::from_slice(&response_bytes)?)
    }
}
