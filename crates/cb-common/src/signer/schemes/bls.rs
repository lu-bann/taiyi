use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsSignature};
use blst::BLST_ERROR;
use tree_hash::TreeHash;

use crate::{
    error::BlstErrorWrapper, signature::sign_commit_boost_root, types::Chain,
    utils::blst_pubkey_to_alloy,
};

pub type BlsSecretKey = blst::min_pk::SecretKey;
pub type BlsPublicKey = alloy::rpc::types::beacon::BlsPublicKey;

#[derive(Clone)]
pub enum BlsSigner {
    Local(BlsSecretKey),
}

impl BlsSigner {
    pub fn new_random() -> Self {
        Self::Local(random_secret())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        let secret = BlsSecretKey::from_bytes(bytes).map_err(BlstErrorWrapper::from)?;
        Ok(Self::Local(secret))
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            BlsSigner::Local(secret) => blst_pubkey_to_alloy(&secret.sk_to_pk()),
        }
    }

    pub fn secret(&self) -> [u8; 32] {
        match self {
            BlsSigner::Local(secret) => secret.clone().to_bytes(),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> BlsSignature {
        match self {
            BlsSigner::Local(sk) => sign_commit_boost_root(chain, sk, object_root),
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> BlsSignature {
        self.sign(chain, msg.tree_hash_root().0).await
    }
}

pub fn random_secret() -> BlsSecretKey {
    use rand::prelude::*;

    let mut rng = rand::rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    match BlsSecretKey::key_gen(&ikm, &[]) {
        Ok(key) => key,
        // Key material is always valid (32 `u8`s), so `key_gen` can't return Err.
        Err(_) => unreachable!(),
    }
}

pub fn verify_bls_signature(
    pubkey: &BlsPublicKey,
    msg: &[u8],
    signature: &BlsSignature,
) -> Result<(), BlstErrorWrapper> {
    use crate::utils::{alloy_pubkey_to_blst, alloy_sig_to_blst};

    let pubkey = alloy_pubkey_to_blst(pubkey)?;
    let signature = alloy_sig_to_blst(signature)?;

    let res = signature.verify(true, msg, BLS_DST_SIG, &[], &pubkey, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(res.into())
    }
}
