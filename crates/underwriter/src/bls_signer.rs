use alloy_primitives::{Address, ChainId, B256};
use alloy_rpc_types_beacon::constants::BLS_DST_SIG;
use taiyi_primitives::bls::{PublicKey, SecretKey, Signature};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];

#[derive(Debug)]
pub struct BlsSigner {
    address: Address,
    chain_id: Option<ChainId>,
    private_key: SecretKey,
    fork_version: [u8; 4],
}

impl BlsSigner {
    pub const fn new(
        address: Address,
        chain_id: Option<ChainId>,
        private_key: SecretKey,
        fork_version: [u8; 4],
    ) -> Self {
        Self { address, chain_id, private_key, fork_version }
    }

    pub async fn sign_hash(&self, hash: &B256) -> Signature {
        let domain = compute_domain(self.fork_version, COMMIT_BOOST_DOMAIN);
        let root = compute_signing_root(hash.0.tree_hash_root().0, domain);
        self.private_key.sign(root.as_ref(), BLS_DST_SIG, &[])
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn public_key(&self) -> PublicKey {
        self.private_key.sk_to_pk()
    }

    pub fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

#[derive(Debug, TreeHash)]
struct ForkData {
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
}

fn compute_domain(fork_version: [u8; 4], domain_mask: [u8; 4]) -> [u8; 32] {
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_mask);

    let fork_data_root =
        ForkData { fork_version, genesis_validators_root: [0; 32] }.tree_hash_root().0;
    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain
}

#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

fn compute_signing_root(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    SigningData { object_root, signing_domain }.tree_hash_root().0
}
