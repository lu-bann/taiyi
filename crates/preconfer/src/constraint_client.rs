use std::time::SystemTime;

use alloy_rpc_types::erc4337;
use eyre::Context;
use reqwest::Url;
use taiyi_primitives::SignedConstraints;
use tracing::{info, warn};

use crate::metrics::preconfer::{PRECONF_CONSTRAINTS_SENT_TIME, RELAY_STATUS_CODE};

/// Client used by commit modules to request signatures via the Signer API
#[derive(Clone)]
pub struct ConstraintClient {
    urls: Vec<Url>,
    client: reqwest::Client,
}

impl ConstraintClient {
    pub fn new(relay_server_address: Vec<String>) -> eyre::Result<Self> {
        let client = reqwest::Client::builder().build()?;

        let urls = relay_server_address
            .into_iter()
            .map(|url| Url::parse(&url).wrap_err("invalid relay server address"))
            .collect::<Result<Vec<Url>, _>>()?;

        Ok(Self { urls, client })
    }

    pub async fn submit_constraints(
        &self,
        constraints: Vec<SignedConstraints>,
    ) -> eyre::Result<()> {
        for url in self.urls.iter() {
            let url = url.join("/constraints/v1/builder/constraints")?;
            info!("Submitting constraints to {}", url);
            let response = self.client.post(url.clone()).json(&constraints).send().await?;
            let code = response.status();

            let body = response.bytes().await.wrap_err("failed to parse response")?;
            let body = String::from_utf8_lossy(&body);

            if code.is_success() {
                info!("Constraints submitted successfully");
            } else {
                warn!("Failed to submit constraints {} {}", body, code);
            }
        }
        Ok(())
    }
}
