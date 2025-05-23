use cb_common::pbs::{GetHeaderResponse, RelayClient};
use reqwest::RequestBuilder;
use tree_hash::{Hash256, TreeHash};

pub trait GetHeaderResponseExt {
    fn message_tree_root(&self) -> Hash256;
}

impl GetHeaderResponseExt for GetHeaderResponse {
    fn message_tree_root(&self) -> Hash256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.tree_hash_root(),
            GetHeaderResponse::Electra(data) => data.message.tree_hash_root(),
        }
    }
}

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
