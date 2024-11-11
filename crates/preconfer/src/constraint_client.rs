use std::time::SystemTime;

use eyre::Context;
use reqwest::Url;
use taiyi_primitives::SignedConstraints;

use crate::metrics::preconfer::{PRECONF_CONSTRAINTS_SENT_TIME, RELAY_STATUS_CODE};

/// Client used by commit modules to request signatures via the Signer API
#[derive(Clone)]
pub struct ConstraintClient {
    url: Url,
    client: reqwest::Client,
}

impl ConstraintClient {
    pub fn new(relay_server_address: String) -> eyre::Result<Self> {
        let client = reqwest::Client::builder().build()?;

        Ok(Self { url: Url::parse(&relay_server_address)?, client })
    }

    pub async fn submit_constraints(
        &self,
        constraints: Vec<SignedConstraints>,
        slot_start_timestamp: u64,
    ) -> eyre::Result<()> {
        let url = self.url.join("constraints/v1/builder/constraints")?;

        let response = self.client.post(url.clone()).json(&constraints).send().await?;
        let code = response.status();

        let body = response.bytes().await.wrap_err("failed to parse response")?;
        let body = String::from_utf8_lossy(&body);
        tracing::info!("Submit constraint Response: {}", body);

        if code.is_success() {
            Ok(())
        } else {
            Err(eyre::eyre!("Failed to submit constraints"))
        }
    }
}
