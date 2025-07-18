use alloy::primitives::{hex, keccak256, Address, B256, U256};
use alloy::sol_types::SolValue as _;
use alloy::{
    consensus::{Transaction, TxEnvelope},
    eips::eip2718::Encodable2718,
};
use serde::{Deserialize, Serialize};

use crate::PreconfFee;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequestTypeA {
    /// ETH transfer to the underwriter
    pub tip_transaction: TxEnvelope,
    /// Preconf transactions from user
    pub preconf_tx: Vec<TxEnvelope>,
    /// Target slot
    pub target_slot: u64,
    /// Relative position of the transaction wrt anchor tx
    pub sequence_number: Option<u64>,
    /// The signer of the request
    pub signer: Address,
    /// The quoted price by the underwriter
    pub preconf_fee: PreconfFee,
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

    pub fn digest(&self, chain_id: u64) -> B256 {
        let mut preconf_txs: Vec<String> = Vec::new();
        for tx in &self.preconf_tx {
            let mut tx_bytes = Vec::new();
            tx.encode_2718(&mut tx_bytes);
            let hex_encoded_tx = format!("0x{}", hex::encode(&tx_bytes));
            preconf_txs.push(hex_encoded_tx);
        }

        let mut tip_tx = Vec::new();
        self.tip_transaction.encode_2718(&mut tip_tx);
        let tip_tx_raw = format!("0x{}", hex::encode(&tip_tx));
        let sequence_number = self.sequence_number.expect("Sequence number should be present");

        keccak256(
            (
                tip_tx_raw,
                preconf_txs,
                U256::from(self.target_slot),
                U256::from(sequence_number),
                self.signer,
                U256::from(chain_id),
            )
                .abi_encode_sequence(),
        )
    }

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
    /// ETH transfer to the underwriter
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

    pub fn value(&self) -> U256 {
        let mut total = self.tip_transaction.value();
        for tx in &self.preconf_transaction {
            total += tx.value();
        }
        total
    }
}
