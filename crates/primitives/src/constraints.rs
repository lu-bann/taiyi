use ethereum_consensus::{
    bellatrix::mainnet::Transaction,
    crypto::Signature,
    ssz::prelude::{SimpleSerialize, *},
};

use self::ssz_rs::List;

pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, SimpleSerialize, Default, PartialEq,
)]
pub struct Constraint {
    pub tx: Transaction,
}

#[derive(
    Debug, Default, Clone, serde::Serialize, serde::Deserialize, SimpleSerialize, PartialEq,
)]
pub struct ConstraintsMessage {
    pub slot: u64,
    pub constraints: List<List<Constraint, MAX_TRANSACTIONS_PER_BLOCK>, MAX_TRANSACTIONS_PER_BLOCK>,
}

impl ConstraintsMessage {
    pub fn new(
        slot: u64,
        constraints: List<List<Constraint, MAX_TRANSACTIONS_PER_BLOCK>, MAX_TRANSACTIONS_PER_BLOCK>,
    ) -> Self {
        Self { slot, constraints }
    }

    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    pub fn len(&self) -> usize {
        self.constraints.len()
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, SimpleSerialize, serde::Deserialize)]
pub struct SignedConstraintsMessage {
    pub message: ConstraintsMessage,
    /// Signature over `message`. Must be signed by the key relating to: `message.public_key`.
    pub signature: Signature,
}

impl SignedConstraintsMessage {
    pub fn new(message: ConstraintsMessage, signature: Signature) -> Self {
        Self { message, signature }
    }
}
