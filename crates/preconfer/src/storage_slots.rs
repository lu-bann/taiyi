use alloy_primitives::{hex::FromHex, StorageKey};
use lazy_static::lazy_static;

lazy_static! {
    /// mapping(address => uint256) public balances
    pub static ref BALANCE_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").expect("");

    /// mapping(address => uint256) public lockBlock
    pub static ref LOCK_BLOCK_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000002").expect("");
}
