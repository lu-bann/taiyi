use alloy_core::primitives::{keccak256, wrap_fixed_bytes, B256, U256};
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
    let contract_name = keccak256("LubanCore".as_bytes());
    let version = keccak256("1.0".as_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(typehash.tokenize().as_ref());
    data.extend_from_slice(contract_name.tokenize().as_ref());
    data.extend_from_slice(version.tokenize().as_ref());
    data.extend_from_slice(chain_id.tokenize().as_ref());
    keccak256(data)
}

#[cfg(test)]
mod tests {
    use alloy_core::primitives::U256;

    use crate::preconf_hash::domain_separator;

    use super::eip712_domain_typehash;

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
            "da358caadda82b600096a11150b79559d2f07fdaac4ddf2425e295c3e432700d"
        );
    }
}
