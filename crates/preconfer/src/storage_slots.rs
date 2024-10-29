use alloy_primitives::{hex::FromHex, StorageKey};
use lazy_static::lazy_static;

lazy_static! {
    /// mapping(address => uint256) public balances
    pub static ref BALANCE_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").expect("");

    /// mapping(address => uint256) public lockBlock
    pub static ref LOCK_BLOCK_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000002").expect("");

    /// mapping(address => uint256) private tipNonceSequenceNumber
    pub static ref TIP_NONCE_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000003").expect("");

    /// mapping(address => uint256) private preconfNonceSequenceNumber
    pub static ref PRECONF_NONCE_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000004").expect("");
}
