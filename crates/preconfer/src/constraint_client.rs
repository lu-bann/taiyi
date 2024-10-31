use std::time::SystemTime;

use ethereum_consensus::deneb::Context;
use reqwest::Url;
use taiyi_primitives::SignedConstraintsMessage;

use crate::metrics::preconfer::{PRECONF_CONSTRAINTS_SENT_TIME, RELAY_STATUS_CODE};

/// Client used by commit modules to request signatures via the Signer API
#[derive(Clone)]
pub struct ConstraintClient {
    context: Context,
    url: Url,
    client: reqwest::Client,
}

impl ConstraintClient {
    pub fn new(context: Context, relay_server_address: String) -> eyre::Result<Self> {
        let client = reqwest::Client::builder().build()?;

        Ok(Self { context, url: Url::parse(&relay_server_address)?, client })
    }

    pub async fn send_set_constraints(
        &self,
        constraint: SignedConstraintsMessage,
    ) -> eyre::Result<()> {
        let url = self.url.join("/eth/v1/builder/set_constraints")?;

        let response = self.client.post(url.clone()).json(&constraint).send().await?;
        let code = response.status();
        RELAY_STATUS_CODE.with_label_values(&[code.as_str(), url.as_str()]).inc();
        let genesis_time = match self.context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.context.min_genesis_time + self.context.genesis_delay,
        };
        let slot_start_timestamp =
            genesis_time + (constraint.message.slot * self.context.seconds_per_slot);
        let slot_start_timestamp_ms = slot_start_timestamp * 1000;
        let now = SystemTime::now();
        let slot_diff_time =
            now.duration_since(SystemTime::UNIX_EPOCH).expect("get system error").as_millis()
                as f64
                - slot_start_timestamp_ms as f64;
        PRECONF_CONSTRAINTS_SENT_TIME
            .with_label_values(&[constraint.message.slot.to_string().as_str()])
            .observe(slot_diff_time);

        if code.is_success() {
            Ok(())
        } else {
            Err(eyre::eyre!("Failed to send constraints"))
        }
    }
}
