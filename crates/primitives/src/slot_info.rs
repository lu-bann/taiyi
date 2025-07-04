use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const GAS_LIMIT: u64 = 30_000_000;
pub const BLOBS_LIMIT: usize = 9;
pub const CONSTRAINTS_LIMIT: u32 = 12;

#[derive(Debug, Error, PartialEq)]
pub enum SlotInfoError {
    #[error("Required gas: {required}. Available: {available}")]
    GasLimit { available: u64, required: u64 },
    #[error("Required blobs: {required}. Available: {available}")]
    BlobLimit { available: usize, required: usize },
    #[error("Required constraints: {required}. Available: {available}")]
    ConstraintLimit { available: u32, required: u32 },
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SlotInfo {
    pub slot: u64,
    pub gas_available: u64,
    pub blobs_available: usize,
    pub constraints_available: u32,
}

pub trait SlotInfoFactory {
    fn slot_info(&self, slot: u64) -> SlotInfo;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HoleskySlotInfoFactory;

impl SlotInfoFactory for HoleskySlotInfoFactory {
    fn slot_info(&self, slot: u64) -> SlotInfo {
        SlotInfo {
            slot,
            gas_available: GAS_LIMIT,
            blobs_available: BLOBS_LIMIT,
            constraints_available: CONSTRAINTS_LIMIT,
        }
    }
}

impl SlotInfo {
    pub const fn new(
        slot: u64,
        gas_available: u64,
        blobs_available: usize,
        constraints_available: u32,
    ) -> Self {
        Self { slot, gas_available, blobs_available, constraints_available }
    }

    pub fn update(
        &mut self,
        gas: u64,
        blobs: usize,
        constraints: u32,
    ) -> Result<(), SlotInfoError> {
        if gas > self.gas_available {
            return Err(SlotInfoError::GasLimit { available: self.gas_available, required: gas });
        }
        if blobs > self.blobs_available {
            return Err(SlotInfoError::BlobLimit {
                available: self.blobs_available,
                required: blobs,
            });
        }
        if constraints > self.constraints_available {
            return Err(SlotInfoError::ConstraintLimit {
                available: self.constraints_available,
                required: constraints,
            });
        }

        self.gas_available -= gas;
        self.blobs_available -= blobs;
        self.constraints_available -= constraints;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_SLOT: u64 = 3;

    #[test]
    fn update_slot_info_succeeds_if_limits_not_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(slot_info.update(gas, blobs, constraints).is_ok());
    }

    #[test]
    fn update_slot_info_fails_if_gas_limit_is_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 101;
        let blobs = 2;
        let constraints = 1;
        let err = slot_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, SlotInfoError::GasLimit { available: gas_limit, required: gas });
    }

    #[test]
    fn update_slot_info_fails_if_gas_limit_is_exceeded_in_two_updates() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(slot_info.update(gas, blobs, constraints).is_ok());

        let gas = 92;
        let blobs = 2;
        let constraints = 1;
        let err = slot_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, SlotInfoError::GasLimit { available: 90, required: gas });
    }

    #[test]
    fn update_slot_info_fails_if_blob_limit_is_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 13;
        let constraints = 1;
        let err = slot_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, SlotInfoError::BlobLimit { available: blob_limit, required: blobs });
    }

    #[test]
    fn update_slot_info_fails_if_blob_limit_is_exceeded_in_two_updates() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(slot_info.update(gas, blobs, constraints).is_ok());

        let gas = 10;
        let blobs = 13;
        let constraints = 1;
        let err = slot_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, SlotInfoError::BlobLimit { available: 10, required: blobs });
    }

    #[test]
    fn update_slot_info_fails_if_constraint_limit_is_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 7;
        let err = slot_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(
            err,
            SlotInfoError::ConstraintLimit { available: constraint_limit, required: constraints }
        );
    }

    #[test]
    fn update_slot_info_fails_if_constraint_limit_is_exceeded_in_two_updates() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut slot_info = SlotInfo::new(DUMMY_SLOT, gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(slot_info.update(gas, blobs, constraints).is_ok());

        let gas = 10;
        let blobs = 2;
        let constraints = 7;
        let err = slot_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, SlotInfoError::ConstraintLimit { available: 4, required: constraints });
    }
}
