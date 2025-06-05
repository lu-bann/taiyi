use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::{PreconfRequestTypeA, PreconfRequestTypeB};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PreconfRequest {
    TypeA(PreconfRequestTypeA),
    TypeB(PreconfRequestTypeB),
}

impl PreconfRequest {
    pub fn target_slot(&self) -> u64 {
        match self {
            PreconfRequest::TypeA(req) => req.target_slot(),
            PreconfRequest::TypeB(req) => req.target_slot(),
        }
    }

    pub fn digest(&self, chain_id: u64) -> B256 {
        match self {
            PreconfRequest::TypeA(req) => req.digest(chain_id),
            PreconfRequest::TypeB(req) => req.digest(chain_id),
        }
    }

    pub fn sequence_num(&self) -> Option<u64> {
        match self {
            PreconfRequest::TypeA(req) => req.sequence_number,
            PreconfRequest::TypeB(_) => None,
        }
    }

    /// Amount to be paid to the underwriter
    pub fn preconf_tip(&self) -> U256 {
        match self {
            PreconfRequest::TypeA(req) => req.preconf_tip(),
            PreconfRequest::TypeB(req) => req.preconf_tip(),
        }
    }

    pub fn signer(&self) -> Address {
        match self {
            PreconfRequest::TypeA(req) => req.signer(),
            PreconfRequest::TypeB(req) => req.signer(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::TxEnvelope;
    use alloy_primitives::{hex, PrimitiveSignature, B256, U256};
    use alloy_provider::network::{Ethereum, EthereumWallet, TransactionBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::{Signature, Signer as _};
    use alloy_signer_local::PrivateKeySigner;
    use uuid::Uuid;

    use super::*;
    use crate::{
        BlockspaceAllocation, PreconfFeeResponse, SubmitTransactionRequest,
        SubmitTypeATransactionRequest,
    };

    const DUMMY_SIGNER_KEY: [u8; 32] =
        hex!("89142DEEB76CEFDCA29BE54970EABE5EAE4392096B148283BA3E684C93950941");

    #[tokio::test]
    async fn test_preconf_request_type_a() -> eyre::Result<()> {
        let signer = PrivateKeySigner::from_slice(&DUMMY_SIGNER_KEY)?;
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
        let preconf_request = PreconfRequest::TypeA(preconf_a.clone());
        assert_eq!(preconf_request.digest(chain_id), digest);
        assert_eq!(preconf_request.signer(), signer.address());
        assert_eq!(preconf_request.sequence_num(), Some(321));
        assert_eq!(preconf_request.preconf_tip(), preconf_a.preconf_tip());
        Ok(())
    }

    #[tokio::test]
    async fn test_preconf_request_type_b() -> eyre::Result<()> {
        let signer = PrivateKeySigner::from_slice(&DUMMY_SIGNER_KEY)?;
        let chain_id = 123;
        let request = PreconfRequestTypeB {
            allocation: BlockspaceAllocation {
                sender: signer.address(),
                recipient: signer.address(), // dont care about recipient in this test
                gas_limit: 21_000,
                deposit: U256::from(1000),
                tip: U256::from(1000),
                target_slot: 1234,
                blob_count: 0,
                preconf_fee: PreconfFeeResponse { gas_fee: 2, blob_gas_fee: 3 },
            },
            alloc_sig: PrimitiveSignature::from_raw(
                // random 65 bytes
                &hex::decode("0x".to_owned() + &"a".repeat(130))?,
            )
            .unwrap(),
            transaction: Some(
                TransactionRequest::default()
                    .with_from(signer.address())
                    .with_to(signer.address())
                    .with_value(U256::from(10000))
                    .with_nonce(777)
                    .with_gas_limit(21_000)
                    .with_max_fee_per_gas(3)
                    .with_max_priority_fee_per_gas(7)
                    .with_chain_id(chain_id)
                    .build(&EthereumWallet::from(signer.clone()))
                    .await?,
            ),
            signer: signer.address(),
        };

        let digest = request.digest(chain_id);
        assert_eq!(
            digest,
            B256::from(hex!("0x45fa702bb7df4114636cb44e1a81bb9fed2c79012e4f652cd42fd53fff2fd406"))
        );
        let preconf_request = PreconfRequest::TypeB(request.clone());
        assert_eq!(preconf_request.digest(123), digest);
        assert_eq!(preconf_request.signer(), signer.address());
        // type B will panic on .sequence_num()
        assert_eq!(preconf_request.sequence_num(), None);
        assert_eq!(preconf_request.preconf_tip(), request.preconf_tip());

        {
            let mut request = request.clone();
            let new_signer = PrivateKeySigner::random();
            request.set_signer(new_signer.address());
            assert_eq!(request.signer(), new_signer.address());
        }
        {
            let mut request = request.clone();
            let new_signer = PrivateKeySigner::random();
            let alloc_sig = new_signer.sign_message("hey there".as_bytes()).await?;
            request.set_alloc_sig(alloc_sig);
            assert_eq!(request.alloc_sig, alloc_sig);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_transaction_request_type_b() -> eyre::Result<()> {
        let signer = PrivateKeySigner::random();
        let tx = {
            let signer = signer.clone();

            let chain_id = 123;
            let sender = signer.address();
            let wallet = EthereumWallet::from(signer);
            let nonce = 1234;
            TransactionRequest::default()
                .with_from(sender)
                .with_value(U256::from(1000))
                .with_nonce(nonce)
                .with_gas_limit(21_000)
                .with_to(sender)
                .with_max_fee_per_gas(2)
                .with_max_priority_fee_per_gas(3)
                .with_chain_id(chain_id)
                .build(&wallet)
                .await?
        };
        let tx_uuid = Uuid::new_v4();
        let request = SubmitTransactionRequest { transaction: tx.clone(), request_id: tx_uuid };
        assert_eq!(SubmitTransactionRequest::new(tx_uuid, tx), request);
        Ok(())
    }
}
