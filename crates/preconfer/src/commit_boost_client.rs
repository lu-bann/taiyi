use alloy::core::primitives::U256;
use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use cb_common::commit::{
    client::GetPubkeysResponse,
    constants::{GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
    request::SignRequest,
};
use jsonrpsee::tracing::debug;
use luban_primitives::PreconfRequest;
use tracing::{error, info};

#[derive(Debug)]
pub struct CommitBoostClient {
    url: String,
    chain_id: U256,
    client: reqwest::Client,
    cb_id: String,
    cb_jwt: String,
}

impl CommitBoostClient {
    pub fn new(url: String, chain_id: U256, cb_id: String, cb_jwt: String) -> Self {
        Self {
            url,
            chain_id,
            client: reqwest::Client::new(),
            cb_id,
            cb_jwt,
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
        info!("Loaded public keys from commit-boost, {pubkeys:?}");
        Ok(pubkeys.consensus)
    }

    pub async fn sign_constraint(
        &self,
        preconf_request: &PreconfRequest,
        pubkey: BlsPublicKey,
    ) -> eyre::Result<BlsSignature> {
        let root = preconf_request.hash(self.chain_id);
        let request = SignRequest::new(self.cb_id.clone(), pubkey, false, root.into());

        let url = format!("{}{REQUEST_SIGNATURE_PATH}", self.url);

        debug!(url, ?request, "Requesting signature from commit_boost");

        let response = reqwest::Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {}", self.cb_jwt))
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

#[cfg(test)]
mod tests {
    use alloy::rpc::types::beacon::BlsSignature;
    use cb_common::commit::{
        client::GetPubkeysResponse,
        constants::{GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
        request::SignRequest,
    };
    use tree_hash::TreeHash;
    use tree_hash_derive::TreeHash;

    #[ignore = "local infra "]
    #[tokio::test]
    async fn request() -> eyre::Result<()> {
        #[derive(TreeHash)]
        struct B {
            a: u64,
        }

        let b = B { a: 15 };
        let root = b.tree_hash_root();
        let pubkey = "0xb03c860f6525f15ed264663fd79b7fcb92115bd763b4f07f36ff0de44fddcabd3f282d6b6d987f751031efa695509c0b".parse().unwrap();
        let request = SignRequest::new("luban", pubkey, false, root.into());

        let url = format!("http://127.0.0.1:8000{REQUEST_SIGNATURE_PATH}");

        let response = reqwest::Client::new()
            .post(url)
            .header(
                "Authorization",
                "Bearer 8d1b71df48ff1971e714156b2aafcac8fc5ea02c6770adc3954557d978ba3439",
            )
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let response_bytes = response.bytes().await?;
        println!("{:?}", status);
        println!("{:?}", response_bytes);
        let sig: BlsSignature = serde_json::from_slice(&response_bytes)?;
        println!("{:?}", sig);
        Ok(())
    }
}
