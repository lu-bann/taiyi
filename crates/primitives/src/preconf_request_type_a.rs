use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, B256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequestTypeA {
    /// Preconf transactions from user
    pub preconf_tx: TxEnvelope,
    /// ETH transfer to the gateway
    pub tip_transaction: TxEnvelope,
    /// Target slot
    pub target_slot: u64,
    /// Relative position of the transaction wrt anchor tx
    pub sequence_num: u64,
    /// The signer of the transaction
    #[serde(skip)]
    pub signer: Option<Address>,
}

impl PreconfRequestTypeA {
    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }

    /// Target slot
    pub fn target_slot(&self) -> u64 {
        self.target_slot
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubmitTypeATransactionRequest {
    /// Preconf transactions from user
    pub preconf_tx: TxEnvelope,
    /// ETH transfer to the gateway
    pub tip_transaction: TxEnvelope,
    /// slot
    pub target_slot: u64,
}

impl SubmitTypeATransactionRequest {
    pub fn new(preconf_tx: TxEnvelope, tip_transaction: TxEnvelope, target_slot: u64) -> Self {
        Self { preconf_tx, tip_transaction, target_slot }
    }

    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(&self.preconf_tx.tx_hash().as_slice());
        digest.extend_from_slice(&self.tip_transaction.tx_hash().as_slice());
        digest.extend_from_slice(&self.target_slot.to_be_bytes());
        keccak256(&digest)
    }
}
