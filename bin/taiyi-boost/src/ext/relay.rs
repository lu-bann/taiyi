use std::time::Duration;

use cb_common::pbs::RelayClient;
use reqwest::RequestBuilder;

pub trait RelayExt {
    fn constraint_stream_request(&self, timeout: Option<u64>) -> eyre::Result<RequestBuilder>;
}

impl RelayExt for RelayClient {
    fn constraint_stream_request(&self, timeout: Option<u64>) -> eyre::Result<RequestBuilder> {
        let url = self.get_url("/relay/v1/builder/constraints_stream")?;
        let request = self.client.get(url).header("header", "text/event-stream");
        if let Some(timeout) = timeout {
            return Ok(request.timeout(Duration::from_secs(timeout)));
        }
        Ok(request)
    }
}
