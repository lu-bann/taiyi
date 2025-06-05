use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

use crate::PreconfFeeResponse;

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
    pub preconf_fee: PreconfFeeResponse,
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
}

#[cfg(test)]
mod tests {

    use super::*;

    use alloy_provider::network::{EthereumWallet, TransactionBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer_local::PrivateKeySigner;

    #[tokio::test]
    async fn test_preconf_type_a() -> eyre::Result<()> {
        let signer = PrivateKeySigner::from_slice(&hex!(
            "89142DEEB76CEFDCA29BE54970EABE5EAE4392096B148283BA3E684C93950941"
        ))?;
        let chain_id = 123;
        let preconf_a = {
            let signer = signer.clone();
            let request = {
                let sender = signer.address();
                let wallet = EthereumWallet::from(signer.clone());
                let nonce = 1234;
                let tip_transaction = TransactionRequest::default()
                    .with_from(sender)
                    .with_value(U256::from(10000))
                    .with_nonce(nonce)
                    .with_gas_limit(21_000)
                    .with_to(sender)
                    .with_max_fee_per_gas(3)
                    .with_max_priority_fee_per_gas(7)
                    .with_chain_id(chain_id)
                    .build(&wallet)
                    .await?;
                let mut preconf_transactions = Vec::new();
                for i in 0..10 {
                    let preconf_transaction = TransactionRequest::default()
                        .with_from(sender)
                        .with_value(U256::from(1000))
                        .with_nonce(nonce + i + 1)
                        .with_gas_limit(21_000)
                        .with_to(sender)
                        .with_max_fee_per_gas((11 * i).into())
                        .with_max_priority_fee_per_gas((5 * i).into())
                        .with_chain_id(chain_id)
                        .build(&wallet)
                        .await?;

                    preconf_transactions.push(TxEnvelope::from(preconf_transaction));
                }
                SubmitTypeATransactionRequest::new(
                    preconf_transactions,
                    TxEnvelope::from(tip_transaction),
                    127,
                )
            };
            assert_eq!(
                request.digest(),
                B256::from(hex!(
                    "0x9cec0d01380d0f4396225099e9a1bcd9634e64d18dcafe306801fda852e4a302"
                ))
            );
            PreconfRequestTypeA {
                tip_transaction: request.tip_transaction,
                preconf_tx: request.preconf_transaction,
                target_slot: request.target_slot,
                sequence_number: Some(321),
                signer: signer.address(),
                preconf_fee: PreconfFeeResponse::default(),
            }
        };

        assert_eq!(preconf_a.signer(), signer.address());

        {
            let mut preconf_a = preconf_a.clone();
            let new_signer = PrivateKeySigner::random();
            preconf_a.set_signer(new_signer.address());
            assert_eq!(preconf_a.signer(), new_signer.address());
            assert_eq!(preconf_a.value(), U256::from(20000));
        }

        let digest = preconf_a.digest(chain_id);
        assert_eq!(
            digest,
            B256::from(hex!("0xa0441c1498b1c6ec409e2279ac00862e16637ec907218c2fd273350aea56ad9b"))
        );
        Ok(())
    }
}
