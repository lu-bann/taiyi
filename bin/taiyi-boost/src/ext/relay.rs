use cb_common::pbs::RelayClient;
use reqwest::RequestBuilder;

pub trait RelayExt {
    fn constraint_stream_request(&self) -> eyre::Result<RequestBuilder>;
}

impl RelayExt for RelayClient {
    fn constraint_stream_request(&self) -> eyre::Result<RequestBuilder> {
        let url = self.get_url("/relay/v1/builder/constraints_stream")?;
        let request = self.client.get(url).header("header", "text/event-stream");
        Ok(request)
    }
}
