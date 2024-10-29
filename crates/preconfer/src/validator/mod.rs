#![allow(dead_code)]
#![allow(unused)]

use alloy_primitives::Address;
use parking_lot::RwLock;
use reth_provider::{providers::ProviderNodeTypes, ProviderFactory};
use reth_revm::primitives::EnvKzgSettings;
use reth_transaction_pool::error::PoolError;
use taiyi_primitives::{PreconfHash, PreconfRequest};

use crate::preconf_pool::PreconfPoolInner;

#[derive(Debug)]
pub struct ValidationJob<N: ProviderNodeTypes> {
    pub provider_factory: ProviderFactory<N>,
}

impl<N: ProviderNodeTypes + Clone + Send + 'static> ValidationJob<N> {
    pub fn new(provider_factory: ProviderFactory<N>) -> Self {
        Self { provider_factory }
    }
}

/// A [`PreconfValidator`] implementation that validates ethereum transaction.
#[derive(Debug, Clone)]
pub struct PreconfValidator {
    /// The current max gas limit
    pub block_gas_limit: u64,
    /// Minimum prepay fee to enforce for acceptance into the pool.
    pub minimum_prepay_fee: Option<u128>,
    /// Stores the setup and parameters needed for validating KZG proofs.
    pub kzg_settings: EnvKzgSettings,
    /// Maximum size in bytes a single transaction can have in order to be accepted into the [`PreconfPool`].
    pub max_tx_input_bytes: usize,
    /// TaiyiCore owner
    pub owner: Address,
}

impl PreconfValidator {
    /// Create a new `TxValidator` instance.
    pub fn new(
        block_gas_limit: u64,
        minimum_prepay_fee: Option<u128>,
        kzg_settings: EnvKzgSettings,
        max_tx_input_bytes: usize,
        owner: Address,
    ) -> Self {
        Self { block_gas_limit, minimum_prepay_fee, kzg_settings, max_tx_input_bytes, owner }
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
