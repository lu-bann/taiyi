use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequestTypeA {
    /// ETH transfer to the gateway
    pub tip_transaction: TxEnvelope,
    /// Preconf transactions from user
    pub preconf_tx: Vec<TxEnvelope>,
    /// Target slot
    pub target_slot: u64,
    /// Relative position of the transaction wrt anchor tx
    pub sequence_number: Option<u64>,
    /// The signer of the request
    pub signer: Address,
}

impl PreconfRequestTypeA {
    /// Returns the transaction signer.
    pub fn signer(&self) -> Address {
        self.signer
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = signer;
    }

    /// Target slot
    pub fn target_slot(&self) -> u64 {
        self.target_slot
    }

    pub fn preconf_tip(&self) -> U256 {
        self.tip_transaction.value()
    }

    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        for tx in &self.preconf_tx {
            digest.extend_from_slice(tx.tx_hash().as_slice());
        }
        digest.extend_from_slice(self.tip_transaction.tx_hash().as_slice());
        digest.extend_from_slice(&self.target_slot.to_be_bytes());
        digest.extend_from_slice(&self.sequence_number.expect("shouldn't be none").to_be_bytes());
        digest.extend_from_slice(self.signer.as_slice());
        keccak256(&digest)
    }

    /// Returns the total value transfer
    pub fn value(&self) -> U256 {
        let mut total = self.tip_transaction.value();
        for tx in &self.preconf_tx {
            total += tx.value();
        }
        total
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubmitTypeATransactionRequest {
    /// ETH transfer to the gateway
    pub tip_transaction: TxEnvelope,
    /// Preconf transactions from user
    pub preconf_transaction: Vec<TxEnvelope>,
    /// slot
    pub target_slot: u64,
}

impl SubmitTypeATransactionRequest {
    pub fn new(
        preconf_transaction: Vec<TxEnvelope>,
        tip_transaction: TxEnvelope,
        target_slot: u64,
    ) -> Self {
        Self { preconf_transaction, tip_transaction, target_slot }
    }

    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(self.tip_transaction.tx_hash().as_slice());
        for tx in &self.preconf_transaction {
            digest.extend_from_slice(tx.tx_hash().as_slice());
        }
        digest.extend_from_slice(&self.target_slot.to_be_bytes());
        keccak256(&digest)
    }
}
