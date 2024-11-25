use alloy_primitives::{hex, B256};
use alloy_rpc_types_beacon::constants::BLS_DST_SIG;
use alloy_signer::{Signature, Signer};
use alloy_signer_local::PrivateKeySigner;
use blst::min_pk::{PublicKey, SecretKey};
use ethereum_consensus::{deneb::Context, primitives::BlsSignature};
use eyre::eyre;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];
pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];

#[derive(Debug, Clone)]
pub struct SignerClient {
    bls: SecretKey,
    ecdsa: PrivateKeySigner,
}

impl SignerClient {
    pub fn new(bls_sk: String, ecdsa_sk: String) -> eyre::Result<Self> {
        let bls =
            SecretKey::from_bytes(&hex::decode(bls_sk.strip_prefix("0x").unwrap_or(&bls_sk))?)
                .map_err(|e| eyre!("Failed decoding preconfer private key: {:?}", e))?;

        let ecdsa = alloy_signer_local::PrivateKeySigner::from_signing_key(
            k256::ecdsa::SigningKey::from_slice(&hex::decode(
                ecdsa_sk.strip_prefix("0x").unwrap_or(&ecdsa_sk),
            )?)?,
        );

        Ok(Self { bls, ecdsa })
    }

    pub async fn sign_with_ecdsa(&self, hash: B256) -> eyre::Result<Signature> {
        Ok(self.ecdsa.sign_hash(&hash).await?)
    }

    pub fn sign_with_bls(&self, context: Context, digest: [u8; 32]) -> eyre::Result<BlsSignature> {
        let domain = compute_domain_custom(&context, COMMIT_BOOST_DOMAIN);
        let root = compute_signing_root_custom(digest.tree_hash_root().0, domain);
        let signature = self.bls.sign(root.as_ref(), BLS_DST_SIG, &[]).to_bytes();
        let signature = BlsSignature::try_from(signature.as_ref()).expect("signature error");
        Ok(signature)
    }

    pub fn bls_pubkey(&self) -> PublicKey {
        self.bls.sk_to_pk()
    }
}

pub fn compute_domain_custom(chain: &Context, domain_mask: [u8; 4]) -> [u8; 32] {
    #[derive(Debug, TreeHash)]
    struct ForkData {
        fork_version: [u8; 4],
        genesis_validators_root: [u8; 32],
    }

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_mask);

    let fork_version = chain.genesis_fork_version;
    let fd = ForkData { fork_version, genesis_validators_root: GENESIS_VALIDATORS_ROOT };
    let fork_data_root = fd.tree_hash_root().0;

    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain
}

pub fn compute_signing_root_custom(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    #[derive(Default, Debug, TreeHash)]
    struct SigningData {
        object_root: [u8; 32],
        signing_domain: [u8; 32],
    }

    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root().0
}
