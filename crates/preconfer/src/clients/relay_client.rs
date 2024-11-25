use ethereum_consensus::{
    primitives::{BlsPublicKey, BlsSignature},
    ssz::prelude::*,
};
use eyre::Context as _;
use reqwest::Url;
use taiyi_primitives::SignedConstraints;
use tracing::{error, info};

use crate::{PATH_BUILDER_API, PATH_BUILDER_DELEGATIONS};

#[derive(Clone)]
pub struct RelayClient {
    client: reqwest::Client,
    urls: Vec<Url>,
}

/// The action type for a delegation message.
pub const DELEGATION_ACTION: u8 = 0;

/// The action type for a revocation message.
pub const REVOCATION_ACTION: u8 = 1;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Hash, PartialEq, Eq)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(
    Debug, Clone, SimpleSerialize, serde::Deserialize, serde::Serialize, Hash, PartialEq, Eq,
)]
pub struct DelegationMessage {
    pub action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl RelayClient {
    pub fn new(relay_urls: Vec<Url>) -> Self {
        Self { client: reqwest::Client::new(), urls: relay_urls }
    }

    pub async fn get_delegations(&self, slot: u64) -> eyre::Result<SignedDelegation> {
        let url = self
            .urls
            .first()
            .expect("relay")
            .join(format!("{PATH_BUILDER_API}{PATH_BUILDER_DELEGATIONS}").as_str())?;
        let response = self.client.get(url).query(&[("slot", slot)]).send().await?;
        let delegation = response.json::<SignedDelegation>().await?;
        Ok(delegation)
    }

    pub async fn set_constraints(&self, constraints: Vec<SignedConstraints>) -> eyre::Result<()> {
        let url = self.urls.first().expect("relay");
        let url = url.join("/constraints/v1/builder/constraints")?;

        let response = self.client.post(url.clone()).json(&constraints).send().await?;
        let code = response.status();

        let body = response.bytes().await.wrap_err("failed to parse response")?;
        let body = String::from_utf8_lossy(&body);

        if code.is_success() {
            info!("Constraints submitted successfully");
        } else {
            error!("Failed to submit constraints {} {}", body, code);
        }

        Ok(())
    }
}
