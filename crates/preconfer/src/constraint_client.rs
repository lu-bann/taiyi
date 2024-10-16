use reqwest::Url;
use taiyi_primitives::SignedConstraintsMessage;

/// Client used by commit modules to request signatures via the Signer API
#[derive(Debug, Clone)]
pub struct ConstraintClient {
    url: Url,
    client: reqwest::Client,
}

impl ConstraintClient {
    pub fn new(relay_server_address: String) -> eyre::Result<Self> {
        let client = reqwest::Client::builder().build()?;

        Ok(Self { url: Url::parse(&relay_server_address)?, client })
    }

    pub async fn send_set_constraints(
        &self,
        constraint: SignedConstraintsMessage,
    ) -> eyre::Result<()> {
        let url = self.url.join("/eth/v1/builder/set_constraints")?;

        let response = self.client.post(url).json(&constraint).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(eyre::eyre!("Failed to send constraints"))
        }
    }
}
