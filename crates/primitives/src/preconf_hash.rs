use alloy_primitives::{keccak256, wrap_fixed_bytes, B256, U256};
use alloy_rlp::bytes;
use alloy_sol_types::SolValue;

wrap_fixed_bytes!(
    extra_derives: [],
    pub struct PreconfHash<32>;
);

#[allow(dead_code)]
pub fn eip712_domain_typehash() -> B256 {
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

#[allow(dead_code)]
pub fn domain_separator(chain_id: U256) -> B256 {
    let typehash = eip712_domain_typehash();
    let contract_name = keccak256("TaiyiCore".as_bytes());
    let version = keccak256("1.0".as_bytes());
    keccak256((typehash, contract_name, version, chain_id).abi_encode_sequence())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::eip712_domain_typehash;
    use crate::preconf_hash::domain_separator;

    #[test]
    fn eip712_domain_typehash_test() {
        let res = eip712_domain_typehash();
        assert_eq!(
            format!("{res:x}"),
            "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
        );
    }

    #[test]
    fn domain_separator_test() {
        let res = domain_separator(U256::from(1337));
        assert_eq!(
            format!("{res:x}"),
            "c5e54e20a9ad29abf87784cb9fe36a45b5ca20222503dd672c344fabc500a581"
        );
    }
}
