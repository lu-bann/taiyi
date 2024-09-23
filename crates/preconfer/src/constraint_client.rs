#![allow(dead_code)]

use std::sync::Arc;

use luban_primitives::SignedConstraintsMessage;

/// Client used by commit modules to request signatures via the Signer API
#[derive(Debug, Clone)]
pub struct ConstraintClient {
    /// Url endpoint of the Signer Module
    url: Arc<String>,
    client: reqwest::Client,
}

impl ConstraintClient {
    pub fn new(relay_server_address: String) -> eyre::Result<Self> {
        let url = format!("http://{relay_server_address}");

        let client = reqwest::Client::builder().build()?;

        Ok(Self { url: url.into(), client })
    }

    pub async fn send_set_constraints(
        &self,
        constraint: SignedConstraintsMessage,
    ) -> eyre::Result<()> {
        let url = format!("{}/eth/v1/builder/set_constraints", self.url);

        let response = self.client.post(&url).json(&constraint).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(eyre::eyre!("Failed to send constraints"))
        }
    }
}
