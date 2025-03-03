use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, PrimitiveSignature, B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequestTypeA {
    pub txs: Vec<B256>,
    pub tip_transaction: Option<TxEnvelope>,
    pub sequence_num: u64,
    /// The signer of the transaction
    #[serde(skip)]
    pub signer: Option<Address>,
}
