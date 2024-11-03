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
    /// Returns hash of the tip tx hash
    /// Mostly used for index preconf request in the preconfer pool
    pub fn hash(&self, chain_id: U256) -> PreconfHash {
        let tip_tx_hash = self.tip_tx.tip_tx_hash(chain_id);
        PreconfHash(tip_tx_hash)
    }

    /// Returns hash of the tip tx
    /// This algorithm is consistent with the solidity code in taiyiCore contract
    pub fn preconf_req_hash(&self, chain_id: U256) -> Option<B256> {
        let mut buffer = Vec::<u8>::new();
        let tip_tx_hash = self.tip_tx.tip_tx_hash(chain_id);
        let preconf_tx_hash = self.preconf_tx.as_ref().map(|tx| tx.hash())?;
        let preconfer_signature = self.preconfer_signature.as_ref().map(|sig| sig.as_bytes())?;
        buffer.extend_from_slice(tip_tx_hash.as_ref());
        buffer.extend_from_slice(preconf_tx_hash.as_ref());
        buffer.extend_from_slice(&self.tip_tx_signature.as_bytes());
        buffer.extend_from_slice(&preconfer_signature);
        Some(keccak256(buffer))
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
        keccak256("TipTx(uint256 gasLimit,address from,address to,uint256 prePay,uint256 afterPay,uint256 nonce,uint256 targetSlot)".as_bytes())
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

    use std::str::FromStr;

    use alloy_primitives::{hex::FromHex, Bytes, Signature, U256};

    use super::{PreconfRequest, TipTransaction};
    use crate::PreconfTx;

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
            "6f8659a050af4ec085b502748f249504c344abfadae8a9308dc52d118c76511a"
        )
    }

    #[test]
    fn test_preconf_request_hash() {
        let tip_tx = TipTransaction::new(
            U256::from(100_000),
            "0xa83114A443dA1CecEFC50368531cACE9F37fCCcb".parse().unwrap(),
            "0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766".parse().unwrap(),
            U256::from(1000),
            U256::from(2000),
            U256::from(1),
            U256::from(1),
        );
        let preconf_tx = PreconfTx::new(
            "0xa83114A443dA1CecEFC50368531cACE9F37fCCcb".parse().unwrap(),
            "0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766".parse().unwrap(),
            U256::from(1000),
            Bytes::from_hex("0x11").unwrap(),
            U256::from(21000),
            U256::from(1),
            Bytes::default(),
            None,
        );

        let preconf_req = PreconfRequest {
            tip_tx: tip_tx.clone(),
            preconf_tx: Some(preconf_tx.clone()),
            tip_tx_signature: Signature::from_str("0x52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c").unwrap(),
            preconfer_signature: Some(Signature::from_str("0x53e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c").unwrap()),
            preconf_req_signature: Some(Signature::from_str("0x42e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c").unwrap()),
        };

        let tip_tx_hash = tip_tx.tip_tx_hash(U256::from(1337));
        assert_eq!(
            format!("{:x}", tip_tx_hash),
            "6f8659a050af4ec085b502748f249504c344abfadae8a9308dc52d118c76511a"
        );
        let preconf_tx_hash = preconf_tx.hash();
        assert_eq!(
            format!("{:x}", preconf_tx_hash),
            "7b61576a8d5323483fd3f578d0adbb469bb77d6674278aeb8550231c0a6e8ff9"
        );
        let preconf_req_hash = preconf_req.preconf_req_hash(U256::from(1337)).unwrap();
        assert_eq!(
            format!("{:x}", preconf_req_hash),
            "c735e25cf49577fe300dbcdbd2d2a51ce2bc97f5b3c8a09c059d769709cd70e3"
        );
    }
}
