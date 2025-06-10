use ethereum_consensus::{
    builder::SignedValidatorRegistration,
    primitives::{BlsPublicKey, BlsSignature},
    ssz::prelude::*,
};
use eyre::Context as _;
use reqwest::Url;
use serde_with::{serde_as, DisplayFromStr};
use taiyi_primitives::SignedConstraints;
use tracing::{debug, error};

use crate::{PATH_BUILDER_API, PATH_BUILDER_DELEGATIONS};

#[derive(Clone)]
pub struct RelayClient {
    client: reqwest::Client,
    urls: Vec<Url>,
}

/// The action type for a delegation message.
pub const DELEGATION_ACTION: u8 = 0;

/// The action type for a revocation message.
pub const _REVOCATION_ACTION: u8 = 1;

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

    pub async fn get_delegations(&self, slot: u64) -> eyre::Result<Vec<SignedDelegation>> {
        let url = self
            .urls
            .first()
            .expect("relay")
            .join(format!("{PATH_BUILDER_API}{PATH_BUILDER_DELEGATIONS}").as_str())?;
        let response = self.client.get(url).query(&[("slot", slot)]).send().await?;
        let body = response.text().await?;
        let delegation = serde_json::from_str::<Vec<SignedDelegation>>(&body)?;
        Ok(delegation)
    }

    pub async fn set_constraints(&self, constraints: Vec<SignedConstraints>) -> eyre::Result<()> {
        let url = self.urls.first().expect("relay").join("/constraints/v1/builder/constraints")?;

        let response = self.client.post(url.clone()).json(&constraints).send().await?;
        let code = response.status();

        let body = response.bytes().await.wrap_err("failed to parse response")?;
        let body = String::from_utf8_lossy(&body);

        if code.is_success() {
            debug!("Constraints submitted successfully");
        } else {
            error!("Failed to submit constraints {} {}", body, code);
        }

        Ok(())
    }

    /// Calls /relay/v1/builder/validators to get "validator registrations for validators scheduled to propose in the current and next epoch."
    /// The result will contain the validators for each slot.
    pub async fn get_current_epoch_validators(&self) -> eyre::Result<Vec<ValidatorSlotData>> {
        let url = self.urls.first().expect("relay").join("/relay/v1/builder/validators")?;
        let req = self.client.get(url);
        let validators = req.send().await?.json::<Vec<ValidatorSlotData>>().await?;
        Ok(validators)
    }
}

/// Info about a registered validator selected as proposer for a slot.
#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSlotData {
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub validator_index: u64,
    pub entry: SignedValidatorRegistration,
}
