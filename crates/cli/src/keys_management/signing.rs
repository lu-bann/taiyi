use alloy_primitives::B256;
use blst::{min_pk::Signature, BLST_ERROR};
use cb_common::constants::COMMIT_BOOST_DOMAIN;
use ethereum_consensus::{
    crypto::PublicKey as BlsPublicKey,
    deneb::{compute_fork_data_root, compute_signing_root, Context as CLContext, Root},
    networks::Network,
};
use eyre::{eyre, Context, Result};

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const BLS_SIGNATURE_BYTES_LEN: usize = 96;

pub fn get_network_fork_version(network: Network) -> Result<[u8; 4]> {
    match network {
        Network::Custom(s) => {
            if s == "hoodi" {
                Ok([16, 0, 9, 16]) // 0x10000910
            } else {
                Err(eyre!("Network {s:?} not supported"))
            }
        }
        _ => {
            let context: CLContext = network.try_into()?;
            Ok(context.genesis_fork_version)
        }
    }
}

/// Helper function to compute the signing root for a message
pub fn compute_commit_boost_signing_root(message: [u8; 32], network: Network) -> Result<B256> {
    let fork_version = get_network_fork_version(network)?;
    compute_signing_root(&message, compute_domain_from_mask(fork_version))
        // Ethereum-consensus uses a different version of alloy so we need to do this cast
        .map(|r| B256::from_slice(r.to_vec().as_slice()))
        .map_err(|e| eyre!("Failed to compute signing root: {}", e))
}

/// Compute the commit boost domain from the fork version
pub fn compute_domain_from_mask(fork_version: [u8; 4]) -> [u8; 32] {
    let mut domain = [0; 32];

    // Note: the application builder domain specs require the genesis_validators_root
    // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
    // same rule.
    let root = Root::default();
    let fork_data_root = compute_fork_data_root(fork_version, root).expect("valid fork data");

    domain[..4].copy_from_slice(&COMMIT_BOOST_DOMAIN);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// Verify the signature with the public key of the signer using the Commit Boost domain.
#[allow(dead_code)]
pub fn verify_commit_boost_root(
    pubkey: BlsPublicKey,
    root: [u8; 32],
    signature: &Signature,
    network: Network,
) -> Result<()> {
    let context: CLContext = network.try_into()?;
    verify_root(pubkey, root, signature, compute_domain_from_mask(context.genesis_fork_version))
}

/// Verify the signature of the object with the given public key.
pub fn verify_root(
    pubkey: BlsPublicKey,
    root: [u8; 32],
    signature: &Signature,
    domain: [u8; 32],
) -> Result<()> {
    let signing_root = compute_signing_root(&root, domain)?;
    let pk = blst::min_pk::PublicKey::from_bytes(pubkey.as_ref()).map_err(|e| eyre!("{:?}", e))?;

    let res = signature.verify(true, signing_root.as_ref(), BLS_DST_PREFIX, &[], &pk, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(eyre!("bls verification failed"))
    }
}

/// Parse a BLS public key from a string
pub fn parse_bls_public_key(underwriter_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = underwriter_pubkey.strip_prefix("0x").unwrap_or(underwriter_pubkey);
    BlsPublicKey::try_from(
        hex::decode(hex_pk).wrap_err("Failed to hex-decode underwriter pubkey")?.as_slice(),
    )
    .map_err(|e| eyre::eyre!("Failed to parse underwriter public key '{}': {}", hex_pk, e))
}
