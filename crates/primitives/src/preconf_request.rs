use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

// use blst::min_sig::Signature
use super::preconf_hash::domain_separator;
use crate::{PreconfHash, PreconfTx};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequest {
    pub tip_tx: TipTransaction,
    pub preconf_tx: Option<PreconfTx>,
    pub tip_tx_signature: Signature,
    pub preconfer_signature: Option<Signature>,
    pub preconf_req_signature: Option<Signature>,
}

impl PreconfRequest {
    /// Returns hash of the tip tx
    pub fn hash(&self, chain_id: U256) -> PreconfHash {
        let mut buffer = Vec::<u8>::new();
        let tip_tx_hash = self.tip_tx.tip_tx_hash(chain_id);
        buffer.extend_from_slice(tip_tx_hash.as_ref());
        PreconfHash(keccak256(buffer))
    }

    pub fn transaction(&self) -> Option<&PreconfTx> {
        self.preconf_tx.as_ref()
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

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
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
        keccak256("TipTx(uint256 gasLimit,address from,address to,uint256 prePay,uint256 afterPay,uint256 nonce,uint256 target_slot)".as_bytes())
    }

    #[allow(dead_code)]
    fn abi_encode(&self) -> Vec<u8> {
        (
            self.gas_limit,
            self.from,
            self.to,
            self.pre_pay,
            self.after_pay,
            self.nonce,
            self.target_slot,
        )
            .abi_encode_sequence()
    }
    #[inline]
    fn _tip_tx_hash(&self) -> B256 {
        let data = (
            Self::typehash(),
            self.gas_limit,
            self.from,
            self.to,
            self.pre_pay,
            self.after_pay,
            self.nonce,
            self.target_slot,
        )
            .abi_encode_sequence();
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

    use alloy_primitives::U256;

    use super::TipTransaction;

    #[test]
    fn test_tip_tx_hash() {
        let tx = TipTransaction::new(
            U256::from(100_000),
            "0xa83114A443dA1CecEFC50368531cACE9F37fCCcb".parse().unwrap(),
            "0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766".parse().unwrap(),
            U256::from(1000),
            U256::from(2000),
            U256::from(1),
            U256::from(1),
        );
        let h = tx.tip_tx_hash(U256::from(1337));
        assert_eq!(
            format!("{:x}", h),
            "200c2a794d5aaf7a95ac301b273412f3e65dca45e052cb513202adcd9a6da79b"
        )
    }
}
