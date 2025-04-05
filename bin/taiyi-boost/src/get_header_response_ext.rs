use alloy_primitives::B256;
use alloy_rpc_types_beacon::BlsSignature;
use cb_common::pbs::GetHeaderResponse;
use tree_hash::{Hash256, TreeHash};

pub trait GetHeaderResponseExt {
    fn transactions_root(&self) -> B256;
    fn parent_hash(&self) -> B256;
    fn signautre(&self) -> BlsSignature;
    fn message_tree_root(&self) -> Hash256;
}

impl GetHeaderResponseExt for GetHeaderResponse {
    fn transactions_root(&self) -> B256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.header.transactions_root,
            GetHeaderResponse::Electra(data) => data.message.header.transactions_root,
        }
    }

    fn parent_hash(&self) -> B256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.header.parent_hash,
            GetHeaderResponse::Electra(data) => data.message.header.parent_hash,
        }
    }

    fn signautre(&self) -> BlsSignature {
        match self {
            GetHeaderResponse::Deneb(data) => data.signature,
            GetHeaderResponse::Electra(data) => data.signature,
        }
    }

    fn message_tree_root(&self) -> Hash256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.tree_hash_root(),
            GetHeaderResponse::Electra(data) => data.signature.tree_hash_root(),
        }
    }
}
