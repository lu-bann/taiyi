use reth_revm::primitives::EnvKzgSettings;
use taiyi_primitives::PreconfRequest;

/// A [`PreconfValidator`] implementation that validates ethereum transaction.
#[derive(Debug, Clone)]
pub struct PreconfValidator {
    /// The current max gas limit
    pub block_gas_limit: u64,
    /// Stores the setup and parameters needed for validating KZG proofs.
    pub kzg_settings: EnvKzgSettings,
    /// Minimum base fee required for a transaction
    pub min_base_fee: u128,
    /// minimum priority fee required for a transaction
    pub min_priority_fee: u128,
}

impl PreconfValidator {
    /// Create a new `TxValidator` instance.
    pub fn new() -> Self {
        Self {
            block_gas_limit: 0,
            kzg_settings: EnvKzgSettings::default(),
            min_base_fee: 0,
            min_priority_fee: 0,
        }
    }
}

#[derive(Debug)]
pub enum ValidationOutcome {
    /// The transaction is considered valid and can be inserted into the sub-pools.
    ///
    /// If simulate is true, the transaction should be sent for simulation against the latest
    /// state for inclusion in the next block. ie. Ready sub-pool.
    /// If simulate is false, the transaction should be parked in the Pending sub-pool.
    Valid {
        /// Whether to propagate the transaction to the simulator.
        simulate: bool,
    },
    /// Preconf request is considered to be valid enough to be included in [`Parked`] sub-pool.
    ParkedValid,
    /// The transaction is considered invalid if it doesn't meet the requirements in [`BlockspaceAllocation`].
    /// The preconfer must call exhaust() function to penalize the sender
    Invalid,
    /// An error occurred while trying to validate the transaction
    Error,
}
