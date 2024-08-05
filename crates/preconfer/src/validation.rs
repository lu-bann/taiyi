#![allow(dead_code)]

use alloy::consensus::TxEnvelope;
use luban_primitives::PreconfRequest;
use reth::primitives::U256;
use thiserror::Error;

use crate::orderpool::priortised_orderpool::{self, PrioritizedOrderPool};

/// Possible commitment validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// The transaction fee is too low to cover the maximum base fee.
    #[error("Transaction fee is too low, need {0} gwei to cover the maximum basefee")]
    BaseFeeTooLow(u128),
    /// The transaction blob fee is too low to cover the maximum blob base fee.
    #[error("Transaction blob fee is too low, need {0} gwei to cover the maximum blob basefee")]
    BlobBaseFeeTooLow(u128),
    /// The max basefee calculation incurred an overflow error.
    #[error("Invalid max basefee calculation: overflow")]
    MaxBaseFeeCalcOverflow,
    /// The transaction nonce is too low.
    #[error("Transaction nonce too low. Expected {0}, got {1}")]
    NonceTooLow(U256, U256),
    /// The transaction nonce is too high.
    #[error("Transaction nonce too high")]
    NonceTooHigh(U256, U256),
    /// The sender account is a smart contract and has code.
    #[error("Account has code")]
    AccountHasCode,
    /// The gas limit is too high.
    #[error("Gas limit too high")]
    GasLimitTooHigh,
    /// The transaction input size is too high.
    #[error("Transaction input size too high")]
    TransactionSizeTooHigh,
    /// Max priority fee per gas is greater than max fee per gas.
    #[error("Max priority fee per gas is greater than max fee per gas")]
    MaxPriorityFeePerGasTooHigh,
    /// The sender does not have enough balance to pay for the transaction.
    #[error("Not enough balance to pay for value + maximum fee")]
    InsufficientBalance,
    /// There are too many EIP-4844 transactions in the target block.
    #[error("Too many EIP-4844 transactions in target block")]
    Eip4844Limit,
    /// The maximum commitments have been reached for the slot.
    #[error("Already requested a preconfirmation for slot {0}. Slot must be >= {0}")]
    SlotTooLow(u64),
    /// The maximum commitments have been reached for the slot.
    #[error("Max commitments reached for slot {0}: {1}")]
    MaxCommitmentsReachedForSlot(u64, usize),
    /// The maximum committed gas has been reached for the slot.
    #[error("Max committed gas reached for slot {0}: {1}")]
    MaxCommittedGasReachedForSlot(u64, u64),
    /// The signature is invalid.
    #[error("Signature error")]
    Signature,
    /// Could not recover signature,
    #[error("Could not recover signer")]
    RecoverSigner,
    /// The transaction chain ID does not match the expected chain ID.
    #[error("Chain ID mismatch")]
    ChainIdMismatch,
    /// NOTE: this should not be exposed to the user.
    #[error("Internal error: {0}")]
    Internal(String),
}

// TDOD: validate all fields
pub fn validate_tx_request(
    tx: &TxEnvelope,
    order: &PreconfRequest,
    priortised_orderpool: &PrioritizedOrderPool,
) -> Result<(), ValidationError> {
    let gas_limit = get_tx_gas_limit(tx);
    if U256::from(gas_limit) > req.tip_tx.gas_limit {
        return Err(ValidationError::GasLimitTooHigh);
    }

    // check nonce
    let nonce = order.tip_tx.nonce;
    let onchain_nonce = U256::from(
        priortised_orderpool
            .onchain_nonces
            .get(&order.tip_tx.from)
            .cloned()
            .unwrap_or_default(),
    );
    let account_nonce = order.nonce();

    // order can't be included
    if onchain_nonce > account_nonce {
        return Err(ValidationError::NonceTooLow(onchain_nonce, account_nonce));
    }

    if onchain_nonce < account_nonce {
        return Err(ValidationError::NonceTooHigh(onchain_nonce, account_nonce));
    }
    Ok(())
}

fn get_tx_gas_limit(tx: &TxEnvelope) -> u128 {
    match tx {
        TxEnvelope::Legacy(t) => t.tx().gas_limit,
        TxEnvelope::Eip2930(t) => t.tx().gas_limit,
        TxEnvelope::Eip1559(t) => t.tx().gas_limit,
        TxEnvelope::Eip4844(t) => t.tx().tx().gas_limit,
        _ => panic!("not implemted"),
    }
}
