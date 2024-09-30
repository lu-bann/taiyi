use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use alloy_rpc_types_beacon::BlsSignature;
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

use super::preconf_hash::domain_separator;
use crate::PreconfHash;

type Transaction = Vec<u8>;

#[derive(Debug, Serialize, Deserialize, Default, Clone, RlpDecodable, RlpEncodable, PartialEq)]
#[rlp(trailing)]
pub struct PreconfRequest {
    pub tip_tx: TipTransaction,
    pub preconf_conditions: PreconfCondition,
    pub init_signature: BlsSignature,
    pub tip_tx_signature: Bytes,
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

    pub fn tip(&self) -> U256 {
        self.tip_tx.after_pay + self.tip_tx.pre_pay
    }

    pub fn nonce(&self) -> U256 {
        self.tip_tx.nonce
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, RlpEncodable, RlpDecodable, Default, PartialEq)]
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
        Self { gas_limit, from, to, pre_pay, after_pay, nonce }
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

#[derive(Debug, Serialize, Deserialize, Clone, RlpEncodable, RlpDecodable, Default, PartialEq)]
pub struct PreconfCondition {
    ordering_meta_data: OrderingMetaData,
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
}

impl PreconfCondition {
    #[allow(dead_code)]
    pub fn new(ordering_meta_data: OrderingMetaData, slot: u64) -> Self {
        Self { ordering_meta_data, slot }
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
        data.extend_from_slice(self.ordering_meta_data.index.tokenize().as_ref());
        data.extend_from_slice(self.slot.tokenize().as_ref());
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

#[derive(Debug, Clone, RlpEncodable, RlpDecodable, Default, Serialize, Deserialize, PartialEq)]
pub struct OrderingMetaData {
    pub index: U256,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};

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
            "ba1fb42f1cb980c90b7db56e0e0d8f2645390e14385c6659e7085d32ec36eed9"
        )
    }

    #[test]
    fn test_preconf_condition_hash() {
        let condition = PreconfCondition::new(super::OrderingMetaData { index: U256::from(0) }, 0);
        let h = condition.preconf_condition_hash(U256::from(1337));
        assert_eq!(
            format!("{:x}", h),
            "3c026982636e294cb0506d712c83ab536260cea9cc6f56d83e8ac79eee4b300e"
        )
    }
}
