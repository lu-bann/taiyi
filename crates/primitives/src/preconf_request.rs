use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

// use blst::min_sig::Signature
use super::preconf_hash::domain_separator;
use crate::PreconfHash;

type Transaction = Vec<u8>;

#[derive(Debug, Serialize, Deserialize, Clone, RlpDecodable, RlpEncodable, PartialEq)]
#[rlp(trailing)]
pub struct PreconfRequest {
    pub tip_tx: TipTransaction,
    pub tip_tx_signature: Signature,
    pub preconf_tx: Option<Transaction>,
    pub preconfer_signature: Option<Signature>,
}

impl PreconfRequest {
    pub fn hash(&self, chain_id: U256) -> PreconfHash {
        let mut buffer = Vec::<u8>::new();
        let tip_tx_hash = self.tip_tx.tip_tx_hash(chain_id);
        buffer.extend_from_slice(tip_tx_hash.as_ref());
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

    pub fn target_slot(&self) -> U256 {
        self.tip_tx.target_slot
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
    pub target_slot: U256,
}

impl TipTransaction {
    pub fn new(
        gas_limit: U256,
        from: Address,
        to: Address,
        pre_pay: U256,
        after_pay: U256,
        nonce: U256,
        target_slot: U256,
    ) -> Self {
        Self { gas_limit, from, to, pre_pay, after_pay, nonce, target_slot }
    }

    #[inline]
    fn typehash() -> B256 {
        keccak256("TipTx(uint256 gasLimit,address from,address to,uint256 prePay,uint256 afterPay,uint256 nonce,uint256 targetSlot)".as_bytes())
    }

    #[inline]
    fn _tip_tx_hash(&self) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(Self::typehash().tokenize().as_ref());
        data.extend_from_slice(self.gas_limit.tokenize().as_ref());
        data.extend_from_slice(self.from.tokenize().as_ref());
        data.extend_from_slice(self.to.tokenize().as_ref());
        data.extend_from_slice(self.pre_pay.tokenize().as_ref());
        data.extend_from_slice(self.after_pay.tokenize().as_ref());
        data.extend_from_slice(self.nonce.tokenize().as_ref());
        data.extend_from_slice(self.target_slot.tokenize().as_ref());
        keccak256(data)
    }

    #[inline]
    pub fn tip_tx_hash(&self, chain_id: U256) -> B256 {
        let mut data = vec![0x19, 0x01];
        data.extend_from_slice(domain_separator(chain_id).as_ref());
        data.extend_from_slice(self._tip_tx_hash().as_ref());
        keccak256(data)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};

    use super::TipTransaction;

    #[test]
    fn test_tip_tx_hash() {
        let tx = TipTransaction::new(
            U256::from(60000),
            Address::ZERO,
            Address::ZERO,
            U256::from(1),
            U256::from(2),
            U256::from(0),
            U256::from(1337),
        );
        let h = tx.tip_tx_hash(U256::from(1337));
        assert_eq!(
            format!("{:x}", h),
            "443916ae266a6c6cc12c602970493707eec22b14620a0fe2d2c773976d7a32ed"
        )
    }
}
