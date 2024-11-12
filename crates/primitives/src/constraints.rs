use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use ethereum_consensus::{
    bellatrix::mainnet::Transaction,
    crypto::{PublicKey as BlsPublicKey, Signature as BlsSignature},
    ssz::prelude::List,
};
use sha2::{Digest, Sha256};
pub const MAX_CONSTRAINTS_PER_SLOT: usize = 256;
/// Trait for any types that can be signed and verified with BLS.
/// This trait is used to abstract over the signing and verification of different types.
pub trait SignableBLS {
    /// Returns the digest of the object.
    fn digest(&self) -> [u8; 32];
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConstraintsMessage {
    pub pubkey: BlsPublicKey,
    pub slot: u64,
    pub top: bool,
    pub transactions: List<Transaction, MAX_CONSTRAINTS_PER_SLOT>,
}

impl SignableBLS for ConstraintsMessage {
    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.pubkey.to_vec());
        hasher.update(self.slot.to_le_bytes());
        hasher.update((self.top as u8).to_le_bytes());
        for tx in self.transactions.iter() {
            // Convert the opaque bytes to a EIP-2718 envelope and obtain the tx hash.
            // this is needed to handle type 3 transactions.
            // FIXME: don't unwrap here and handle the error properly
            let tx_bytes = tx.to_vec();
            let tx = TxEnvelope::network_decode(&mut tx_bytes.as_ref()).expect("tx decode error");
            hasher.update(tx.tx_hash());
        }

        hasher.finalize().into()
    }
}
