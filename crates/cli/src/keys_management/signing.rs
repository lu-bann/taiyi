use alloy_primitives::B256;
use eyre::{Context, Result};
use ssz_rs::prelude::*;
use taiyi_crypto::bls::PublicKey as BlsPublicKey;
use tree_hash::TreeHash;

pub const DOMAIN: [u8; 4] = [109, 109, 111, 67];

/// The BLS Domain Separator used in Ethereum 2.0.
// pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const BLS_SIGNATURE_BYTES_LEN: usize = 96;

/// Helper struct to compute the signing root for a given object
/// root and signing domain as defined in the Ethereum 2.0 specification.
#[derive(Default, Debug, tree_hash_derive::TreeHash)]
struct SigningData {
    object_root: B256,
    signing_domain: [u8; 32],
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize, tree_hash_derive::TreeHash)]
pub struct ForkData {
    pub current_version: [u8; 4],
    pub genesis_validators_root: B256,
}

pub fn compute_fork_data_root(current_version: [u8; 4], genesis_validators_root: B256) -> B256 {
    ForkData { current_version, genesis_validators_root }.tree_hash_root()
}

/// Compute the signing root for a given object root and signing domain.
pub fn compute_signing_root(ssz_object: [u8; 32], signing_domain: [u8; 32]) -> Result<B256> {
    let object_root = ssz_object.hash_tree_root()?;
    let signing_data = SigningData { object_root, signing_domain };
    Ok(B256::from_slice(signing_data.tree_hash_root().0.as_slice()))
}

/// Helper function to compute the signing root for a message
pub fn compute_commit_boost_signing_root(message: [u8; 32], fork_version: [u8; 4]) -> Result<B256> {
    compute_signing_root(message, compute_domain_from_mask(fork_version))
}

/// Compute the commit boost domain from the fork version
pub fn compute_domain_from_mask(fork_version: [u8; 4]) -> [u8; 32] {
    let mut domain = [0; 32];

    // Note: the application builder domain specs require the genesis_validators_root
    // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
    // same rule.
    let root = B256::default();
    let fork_data_root = compute_fork_data_root(fork_version, root);

    domain[..4].copy_from_slice(&DOMAIN);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

// /// Verify the signature of the object with the given public key.
// pub fn verify_root(
//     pubkey: BlsPublicKey,
//     root: [u8; 32],
//     signature: &Signature,
//     domain: [u8; 32],
// ) -> Result<()> {
//     let signing_root = compute_signing_root(&root, domain)?;
//     // let res = signature.verify(true, signing_root.as_ref(), BLS_DST_PREFIX, &[], &pubkey, true);
//     // if res == BLST_ERROR::BLST_SUCCESS {
//     //     Ok(())
//     // } else {
//     //     Err(eyre!("bls verification failed"))
//     // }
//     Ok(())
// }

/// Parse a BLS public key from a string
pub fn parse_bls_public_key(underwriter_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = underwriter_pubkey.strip_prefix("0x").unwrap_or(underwriter_pubkey);
    BlsPublicKey::deserialize(
        hex::decode(hex_pk).wrap_err("Failed to hex-decode underwriter pubkey")?.as_slice(),
    )
    .map_err(|e| eyre::eyre!("Failed to parse underwriter public key '{}': {:?}", hex_pk, e))
}
