use cb_common::pbs::GetHeaderResponse;
use tree_hash::{Hash256, TreeHash};

pub trait GetHeaderResponseExt {
    fn message_tree_root(&self) -> Hash256;
}

impl GetHeaderResponseExt for GetHeaderResponse {
    fn message_tree_root(&self) -> Hash256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.tree_hash_root(),
            GetHeaderResponse::Electra(data) => data.signature.tree_hash_root(),
        }
    }
}
