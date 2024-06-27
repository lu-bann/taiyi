use alloy_consensus::TxEnvelope;
use alloy_core::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_core::rlp::{RlpDecodable, RlpEncodable};
use alloy_rlp::Decodable;
use alloy_rpc_types_beacon::BlsSignature;

use super::preconf_hash::domain_separator;
use crate::PreconfHash;
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

type Transaction = Vec<u8>;

#[derive(
    Debug, Serialize, Deserialize, Default, Clone, RlpDecodable, RlpEncodable, Encode, Decode,
)]
#[rlp(trailing)]
pub struct PreconfRequest {
    pub tip_tx: TipTransaction,
    pub preconf_conditions: PreconfCondition,
    pub init_signature: BlsSignature,
    tip_tx_signature: Bytes,
    pub preconfer_signature: Bytes,
    pub preconf_tx: Option<Transaction>,
}

impl PreconfRequest {
    pub fn hash(&self, chain_id: U256) -> PreconfHash {
        let mut buffer = Vec::<u8>::new();
        let tip_tx_hash = self.tip_tx.tip_tx_hash(chain_id);
        buffer.extend_from_slice(tip_tx_hash.as_ref());
        let preconf_conditions_hash = self.preconf_conditions.preconf_condition_hash(chain_id);
        buffer.extend_from_slice(preconf_conditions_hash.as_ref());
        PreconfHash(keccak256(buffer))
    }

    pub fn transaction(&self) -> Result<Option<TxEnvelope>, alloy_rlp::Error> {
        if let Some(preconf_tx) = &self.preconf_tx {
            let mut tx_decoded = preconf_tx.as_slice();
            TxEnvelope::decode(&mut tx_decoded).map(Some)
        } else {
            Ok(None)
        }
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, RlpEncodable, RlpDecodable, Default, Encode, Decode,
)]
pub struct TipTransaction {
    pub gas_limit: U256,
    pub from: Address,
    pub to: Address,
    pub pre_pay: U256,
    pub after_pay: U256,
    pub nonce: U256,
}

impl TipTransaction {
    #[allow(dead_code)]
    pub fn new(
        gas_limit: U256,
        from: Address,
        to: Address,
        pre_pay: U256,
        after_pay: U256,
        nonce: U256,
    ) -> Self {
        Self {
            gas_limit,
            from,
            to,
            pre_pay,
            after_pay,
            nonce,
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn typehash() -> B256 {
        keccak256("TipTx(uint256 gasLimit,address from,address to,uint256 prePay,uint256 afterPay)")
    }

    #[inline]
    #[allow(dead_code)]
    fn _tip_tx_hash(&self) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(Self::typehash().tokenize().as_ref());
        data.extend_from_slice(self.gas_limit.tokenize().as_ref());
        data.extend_from_slice(self.from.tokenize().as_ref());
        data.extend_from_slice(self.to.tokenize().as_ref());
        data.extend_from_slice(self.pre_pay.tokenize().as_ref());
        data.extend_from_slice(self.after_pay.tokenize().as_ref());
        data.extend_from_slice(self.nonce.tokenize().as_ref());
        keccak256(data)
    }

    #[inline]
    #[allow(dead_code)]
    pub fn tip_tx_hash(&self, chain_id: U256) -> B256 {
        let mut data = vec![0x19, 0x01];
        data.extend_from_slice(domain_separator(chain_id).as_ref());
        data.extend_from_slice(self._tip_tx_hash().as_ref());
        keccak256(data)
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, RlpEncodable, RlpDecodable, Default, Encode, Decode,
)]
pub struct PreconfCondition {
    inclusion_meta_data: InclusionMetaData,
    ordering_meta_data: OrderingMetaData,
    pub block_number: u64,
}

impl PreconfCondition {
    #[allow(dead_code)]
    pub fn new(
        inclusion_meta_data: InclusionMetaData,
        ordering_meta_data: OrderingMetaData,
        block_number: u64,
    ) -> Self {
        Self {
            inclusion_meta_data,
            ordering_meta_data,
            block_number,
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn typehash() -> B256 {
        keccak256("PreconfConditions(InclusionMeta inclusionMetaData,OrderingMeta orderingMetaData,uint256 blockNumber)")
    }

    #[inline]
    fn _preconf_condition_hash(&self) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(Self::typehash().tokenize().as_ref());
        data.extend_from_slice(
            self.inclusion_meta_data
                .starting_block_number
                .tokenize()
                .as_ref(),
        );
        data.extend_from_slice(
            self.ordering_meta_data
                .transaction_count
                .tokenize()
                .as_ref(),
        );
        data.extend_from_slice(self.ordering_meta_data.index.tokenize().as_ref());
        data.extend_from_slice(self.block_number.tokenize().as_ref());
        keccak256(data)
    }

    #[allow(dead_code)]
    pub fn preconf_condition_hash(&self, chain_id: U256) -> B256 {
        let mut data = vec![0x19, 0x01];
        data.extend_from_slice(domain_separator(chain_id).as_ref());
        data.extend_from_slice(self._preconf_condition_hash().as_ref());
        keccak256(data)
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, RlpEncodable, RlpDecodable, Default, Encode, Decode,
)]
pub struct InclusionMetaData {
    starting_block_number: U256,
}

#[derive(
    Debug, Clone, RlpEncodable, RlpDecodable, Default, Serialize, Deserialize, Encode, Decode,
)]
pub struct OrderingMetaData {
    transaction_count: U256,
    index: U256,
}

#[cfg(test)]
mod tests {
    use alloy_core::primitives::{Address, U256};

    use super::{PreconfCondition, TipTransaction};

    #[test]
    fn test_tip_tx_hash() {
        let tx = TipTransaction::new(
            U256::from(60000),
            Address::ZERO,
            Address::ZERO,
            U256::from(1),
            U256::from(2),
            U256::from(0),
        );
        let h = tx.tip_tx_hash(U256::from(1337));
        assert_eq!(
            format!("{:x}", h),
            "4ab6b3fdf276cc7aba6ac7de4ca4a737fac1ba57f4f473cd6268dc12160489d9"
        )
    }

    #[test]
    fn test_preconf_condition_hash() {
        let condition = PreconfCondition::new(
            super::InclusionMetaData {
                starting_block_number: U256::from(0),
            },
            super::OrderingMetaData {
                transaction_count: U256::from(0),
                index: U256::from(0),
            },
            0,
        );
        let h = condition.preconf_condition_hash(U256::from(1337));
        assert_eq!(
            format!("{:x}", h),
            "f0161900bacb2493c1a2f39437d5f6b7d5c995a02127e7d9ddcf3e78fdd10dea"
        )
    }
}
