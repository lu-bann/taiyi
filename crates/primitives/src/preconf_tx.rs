use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

// Define the PreconfTx struct in Rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreconfTx {
    pub from: Address,        // Ethereum address
    pub to: Address,          // Ethereum address
    pub value: U256,          // Transaction value
    pub call_data: Bytes,     // Transaction calldata bytes
    pub call_gas_limit: U256, // Gas limit for the call
    pub nonce: U256,          // Transaction nonce which depends on the contract
    pub signature: Bytes,     // Transaction ECDSA signature bytes
    pub permit_data: Option<PermitData>,
}

impl PreconfTx {
    // Constructor for PreconfTx
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        from: Address,
        to: Address,
        value: U256,
        call_data: Bytes,
        call_gas_limit: U256,
        nonce: U256,
        signature: Bytes,
        permit_data: Option<PermitData>,
    ) -> Self {
        PreconfTx { from, to, value, call_data, call_gas_limit, nonce, signature, permit_data }
    }

    pub fn abi_encode(&self) -> Bytes {
        (self.from, self.to, self.value, self.call_data.clone(), self.call_gas_limit, self.nonce)
            .abi_encode_sequence()
            .into()
    }

    pub fn hash(&self) -> B256 {
        keccak256(self.abi_encode())
    }

    pub fn gas_limit(&self) -> U256 {
        self.call_gas_limit
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermitData {
    pub value: U256,
    pub deadline: U256,
    pub v: u8,
    pub r: B256,
    pub s: B256,
}

#[cfg(test)]
mod tests {

    use alloy_primitives::hex::FromHex;

    use super::*;
    #[test]
    fn preconf_tx_hash() {
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

        let hash = preconf_tx.hash();
        assert_eq!(
            format!("{hash:x}"),
            "7b61576a8d5323483fd3f578d0adbb469bb77d6674278aeb8550231c0a6e8ff9"
        );
    }

    #[test]
    fn preconf_tx_empty_calldata_hash() {
        let preconf_tx = PreconfTx::new(
            "0xa83114A443dA1CecEFC50368531cACE9F37fCCcb".parse().unwrap(),
            "0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766".parse().unwrap(),
            U256::from(1000),
            Bytes::default(),
            U256::from(21000),
            U256::from(1),
            Bytes::default(),
            None,
        );

        let hash = preconf_tx.hash();
        assert_eq!(
            format!("{hash:x}"),
            "5db8eee818de95bee126e27f278d765b7ef486865e46395e991b8527be726c7d"
        );
    }
}
