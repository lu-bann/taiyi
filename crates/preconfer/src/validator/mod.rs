#![allow(dead_code)]
#![allow(unused)]

use reth_revm::primitives::EnvKzgSettings;
use taiyi_primitives::{PreconfHash, PreconfRequest};

mod constant;

/// A [`PreconfValidator`] implementation that validates ethereum transaction.
#[derive(Debug, Clone)]
pub(crate) struct PreconfValidator {
    /// The current max gas limit
    block_gas_limit: u64,
    /// Minimum prepay fee to enforce for acceptance into the pool.
    minimum_prepay_fee: Option<u128>,
    /// Stores the setup and parameters needed for validating KZG proofs.
    kzg_settings: EnvKzgSettings,
    /// Maximum size in bytes a single transaction can have in order to be accepted into the [`PreconfPool`].
    max_tx_input_bytes: usize,
}

impl PreconfValidator {
    /// Create a new `TxValidator` instance.
    pub fn new(
        block_gas_limit: u64,
        minimum_prepay_fee: Option<u128>,
        kzg_settings: EnvKzgSettings,
        max_tx_input_bytes: usize,
    ) -> Self {
        Self { block_gas_limit, minimum_prepay_fee, kzg_settings, max_tx_input_bytes }
    }

    pub(crate) fn validate(&self, _preconf_req: &PreconfRequest) -> ValidationOutcome {
        // Validate the transaction
        todo!()
    }
}

#[derive(Debug)]
pub(crate) enum ValidationOutcome {
    /// The transaction is considered valid and can be inserted into the sub-pools.
    ///
    /// If simulate is true, the transaction should be sent for simulation against the latest
    /// state for inclusion in the next block. ie. Ready sub-pool.
    /// If simulate is false, the transaction should be parked in the Pending sub-pool.
    Valid {
        /// Whether to propagate the transaction to the simulator.
        simulate: bool,
        preconf_hash: PreconfHash,
    },
    /// Preconf request is considered to be valid enough to be included in [`Parked`] sub-pool.
    ParkedValid(PreconfHash),
    /// The transaction is considered invalid if it doesn't meet the requirements sent in [`TipTx`].
    /// The preconfer must call exhaust() function to invalidate the soft-commitment.
    Invalid(PreconfHash),
    /// An error occurred while trying to validate the transaction
    Error,
}
