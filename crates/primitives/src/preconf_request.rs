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
    use alloy_provider::network::{EthereumWallet, TransactionBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::Signer as _;
    use alloy_signer_local::PrivateKeySigner;
    use uuid::Uuid;

    use super::*;
    use crate::{
        BlockspaceAllocation, PreconfFeeResponse, SubmitTransactionRequest,
        SubmitTypeATransactionRequest,
    };

    const DUMMY_CHAIN_ID: u64 = 123;
    const DUMMY_NONCE: u64 = 1234;
    const DUMMY_SIGNER_KEY: [u8; 32] =
        hex!("89142DEEB76CEFDCA29BE54970EABE5EAE4392096B148283BA3E684C93950941");
    const DUMMY_RECIPIENT: [u8; 20] = hex!("0x0478479B6891D746176d76d30126479bBF3d1669");
    const DUMMY_TX_VALUE: u64 = 10000;
    const DUMMY_MAX_FEE_PER_GAS: u64 = 3;
    const DUMMY_MAX_PRIORITY_FEE_PER_GAS: u64 = 7;
    const DUMMY_SEQUENCE_NUMBER: Option<u64> = Some(321);
    const DUMMY_GAS_LIMIT: u64 = 21000;
    const DUMMY_TARGET_SLOT: u64 = 127;

    #[tokio::test]
    async fn test_preconf_request_type_a() -> eyre::Result<()> {
        const NUM_PRECONF_TX: u64 = 10;

        let signer = PrivateKeySigner::from_slice(&DUMMY_SIGNER_KEY)?;

        let preconf_a = {
            let signer = signer.clone();
            let request = {
                let sender = signer.address();
                let wallet = EthereumWallet::from(signer.clone());
                let tip_transaction = TransactionRequest::default()
                    .with_from(sender)
                    .with_value(U256::from(DUMMY_TX_VALUE))
                    .with_nonce(DUMMY_NONCE)
                    .with_gas_limit(DUMMY_GAS_LIMIT)
                    .with_to(sender)
                    .with_max_fee_per_gas(DUMMY_MAX_FEE_PER_GAS.into())
                    .with_max_priority_fee_per_gas(DUMMY_MAX_PRIORITY_FEE_PER_GAS.into())
                    .with_chain_id(DUMMY_CHAIN_ID)
                    .build(&wallet)
                    .await?;
                let mut preconf_transactions = Vec::new();
                for i in 0..NUM_PRECONF_TX {
                    let preconf_transaction = TransactionRequest::default()
                        .with_from(sender)
                        .with_value(U256::from(DUMMY_TX_VALUE / NUM_PRECONF_TX))
                        .with_nonce(DUMMY_NONCE + i + 1)
                        .with_gas_limit(DUMMY_GAS_LIMIT)
                        .with_to(sender)
                        .with_max_fee_per_gas(DUMMY_MAX_FEE_PER_GAS.into())
                        .with_max_priority_fee_per_gas(DUMMY_MAX_PRIORITY_FEE_PER_GAS.into())
                        .with_chain_id(DUMMY_CHAIN_ID)
                        .build(&wallet)
                        .await?;

                    preconf_transactions.push(TxEnvelope::from(preconf_transaction));
                }
                SubmitTypeATransactionRequest::new(
                    preconf_transactions,
                    TxEnvelope::from(tip_transaction),
                    DUMMY_TARGET_SLOT,
                )
            };
            assert_eq!(
                request.digest(),
                B256::from(hex!(
                    "0x8fb9701b2cd0ba70bb2ec821affc0401f7e738a5f9c9e40f1485e3c0a64d0934"
                ))
            );
            PreconfRequestTypeA {
                tip_transaction: request.tip_transaction,
                preconf_tx: request.preconf_transaction,
                target_slot: request.target_slot,
                sequence_number: DUMMY_SEQUENCE_NUMBER,
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

        let digest = preconf_a.digest(DUMMY_CHAIN_ID);
        assert_eq!(
            digest,
            B256::from(hex!("0xf1386c6cc909a1b04d6d1a4cbd85b055b4223f2844675a7f8d25b5f77409d0bf"))
        );
        let preconf_request = PreconfRequest::TypeA(preconf_a.clone());
        assert_eq!(preconf_request.digest(DUMMY_CHAIN_ID), digest);
        assert_eq!(preconf_request.signer(), signer.address());
        assert_eq!(preconf_request.sequence_num(), DUMMY_SEQUENCE_NUMBER);
        assert_eq!(preconf_request.preconf_tip(), preconf_a.preconf_tip());
        Ok(())
    }

    #[tokio::test]
    async fn test_preconf_request_type_b() -> eyre::Result<()> {
        let signer = PrivateKeySigner::from_slice(&DUMMY_SIGNER_KEY)?;
        let request = PreconfRequestTypeB {
            allocation: BlockspaceAllocation {
                sender: signer.address(),
                recipient: DUMMY_RECIPIENT.into(),
                gas_limit: DUMMY_GAS_LIMIT,
                deposit: U256::from(1000),
                tip: U256::from(1000),
                target_slot: 1234,
                blob_count: 0,
                preconf_fee: PreconfFeeResponse { gas_fee: 2, blob_gas_fee: 3 },
            },
            alloc_sig: PrimitiveSignature::from_raw([0u8; 65].as_slice()).unwrap(),
            transaction: Some(
                TransactionRequest::default()
                    .with_from(signer.address())
                    .with_to(DUMMY_RECIPIENT.into())
                    .with_value(U256::from(DUMMY_TX_VALUE))
                    .with_nonce(DUMMY_NONCE)
                    .with_gas_limit(DUMMY_GAS_LIMIT)
                    .with_max_fee_per_gas(DUMMY_MAX_FEE_PER_GAS.into())
                    .with_max_priority_fee_per_gas(DUMMY_MAX_PRIORITY_FEE_PER_GAS.into())
                    .with_chain_id(DUMMY_CHAIN_ID)
                    .build(&EthereumWallet::from(signer.clone()))
                    .await?,
            ),
            signer: signer.address(),
        };

        let preconf_request = PreconfRequest::TypeB(request.clone());
        assert_eq!(
            preconf_request.digest(DUMMY_CHAIN_ID),
            B256::from(hex!("0xb70fcd98ec7d0f5c209cd107af2d04342724c44f66431648e3e49479a83ca7cd"))
        );
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

            let sender = signer.address();
            let wallet = EthereumWallet::from(signer);
            let nonce = 1234;
            TransactionRequest::default()
                .with_from(sender)
                .with_value(U256::from(DUMMY_TX_VALUE))
                .with_nonce(nonce)
                .with_gas_limit(DUMMY_GAS_LIMIT)
                .with_to(sender)
                .with_max_fee_per_gas(DUMMY_MAX_FEE_PER_GAS.into())
                .with_max_priority_fee_per_gas(DUMMY_MAX_PRIORITY_FEE_PER_GAS.into())
                .with_chain_id(DUMMY_CHAIN_ID)
                .build(&wallet)
                .await?
        };
        let tx_uuid = Uuid::new_v4();
        let request = SubmitTransactionRequest { transaction: tx.clone(), request_id: tx_uuid };
        assert_eq!(SubmitTransactionRequest::new(tx_uuid, tx), request);
        Ok(())
    }
}
