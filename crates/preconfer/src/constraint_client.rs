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

    pub async fn send_set_constraints(
        &self,
        constraints: Vec<SignedConstraints>,
        slot_start_timestamp: u64,
    ) -> eyre::Result<()> {
        let url = self.url.join("/constraints/v1/builder/constraints")?;

        let response = self.client.post(url.clone()).json(&constraints).send().await?;
        let code = response.status();
        RELAY_STATUS_CODE.with_label_values(&[code.as_str(), url.as_str()]).inc();
        for constraint in constraints.iter() {
            let now = SystemTime::now();
            let slot_diff_time =
                now.duration_since(SystemTime::UNIX_EPOCH).expect("get system error").as_millis()
                    as f64
                    - (slot_start_timestamp * 1000) as f64;
            PRECONF_CONSTRAINTS_SENT_TIME
                .with_label_values(&[constraint.message.slot.to_string().as_str()])
                .observe(slot_diff_time);
        }

        let body = response.bytes().await.wrap_err("failed to parse response")?;
        let body = String::from_utf8_lossy(&body);
        tracing::info!("Submit constraint Response: {}", body);

        if code.is_success() {
            Ok(())
        } else {
            Err(eyre::eyre!("Failed to send constraints"))
        }
    }
}
