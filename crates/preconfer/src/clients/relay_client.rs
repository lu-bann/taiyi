use ethereum_consensus::{
    primitives::{BlsPublicKey, BlsSignature},
    ssz::prelude::*,
};
use eyre::Context as _;
use reqwest::Url;
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
        let url = self.urls.first().expect("relay");
        let url = url.join("/constraints/v1/builder/constraints")?;

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
}

#[cfg(test)]
mod tests {

    use crate::clients::relay_client::SignedDelegation;

    #[ignore = "Fix this test"]
    #[test]
    fn test_get_signed_delegations() -> eyre::Result<()> {
        let res = get_signed_delegations();
        let signed_delegation: Vec<SignedDelegation> = serde_json::from_str(res)?;
        let signed_delegation = signed_delegation.first().unwrap();
        assert_eq!(signed_delegation.message.action, super::DELEGATION_ACTION);

        assert_eq!(
            signed_delegation.message.validator_pubkey.to_string(),
            "0x882c02d0c1c30cf9bb84769fc37bf81a73795be9799156ac3a500fba24ddae4f310b47dc27c08e1acdf395a0d9e5ae6a"
        );

        assert_eq!(
            signed_delegation.message.delegatee_pubkey.to_string(),
            "0xa30e3c596a76f109094afbc16689adab5c03fb575213085d3e3a0766d269a961e28dd909312408866c6d481fc8a93522"
        );
        Ok(())
    }

    fn get_signed_delegations() -> &'static str {
        r#"
        [{
            "message": 
            {
            "action": 0,
            "validator_pubkey": "0x882c02d0c1c30cf9bb84769fc37bf81a73795be9799156ac3a500fba24ddae4f310b47dc27c08e1acdf395a0d9e5ae6a",
            "delegatee_pubkey": "0xa30e3c596a76f109094afbc16689adab5c03fb575213085d3e3a0766d269a961e28dd909312408866c6d481fc8a93522"
            },
            "signature": "0xb067c33c6b8018086ba0b294e069063d185a01116475caa6e4cf36d08d62422ad68ef83ec0b01b4e13dfd95a914f2ed50301e1bfd945d0339b11a0330b06bd532a8bb9cd8017452e1f44f7c64c1ab4888266e87f99c916c90d5fd95614b0dfc4"
        }]"#
    }
}
