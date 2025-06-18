use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum BlockInfoError {
    #[error("Required gas: {required}. Available: {available}")]
    GasLimit { available: u64, required: u64 },
    #[error("Required blobs: {required}. Available: {available}")]
    BlobLimit { available: usize, required: usize },
    #[error("Required constraints: {required}. Available: {available}")]
    ConstraintLimit { available: u32, required: u32 },
}

#[derive(Debug, Clone, Copy)]
pub struct BlockInfo {
    remaining_gas: u64,
    remaining_blobs: usize,
    remaining_constraints: u32,
}

impl BlockInfo {
    pub const fn new(
        remaining_gas: u64,
        remaining_blobs: usize,
        remaining_constraints: u32,
    ) -> Self {
        Self { remaining_gas, remaining_blobs, remaining_constraints }
    }

    pub fn update(
        &mut self,
        gas: u64,
        blobs: usize,
        constraints: u32,
    ) -> Result<(), BlockInfoError> {
        if gas > self.remaining_gas {
            return Err(BlockInfoError::GasLimit { available: self.remaining_gas, required: gas });
        }
        if blobs > self.remaining_blobs {
            return Err(BlockInfoError::BlobLimit {
                available: self.remaining_blobs,
                required: blobs,
            });
        }
        if constraints > self.remaining_constraints {
            return Err(BlockInfoError::ConstraintLimit {
                available: self.remaining_constraints,
                required: constraints,
            });
        }

        self.remaining_gas -= gas;
        self.remaining_blobs -= blobs;
        self.remaining_constraints -= constraints;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_block_info_succeeds_if_limits_not_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(block_info.update(gas, blobs, constraints).is_ok());
    }

    #[test]
    fn update_block_info_fails_if_gas_limit_is_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 101;
        let blobs = 2;
        let constraints = 1;
        let err = block_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, BlockInfoError::GasLimit { available: gas_limit, required: gas });
    }

    #[test]
    fn update_block_info_fails_if_gas_limit_is_exceeded_in_two_updates() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(block_info.update(gas, blobs, constraints).is_ok());

        let gas = 92;
        let blobs = 2;
        let constraints = 1;
        let err = block_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, BlockInfoError::GasLimit { available: 90, required: gas });
    }

    #[test]
    fn update_block_info_fails_if_blob_limit_is_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 13;
        let constraints = 1;
        let err = block_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, BlockInfoError::BlobLimit { available: blob_limit, required: blobs });
    }

    #[test]
    fn update_block_info_fails_if_blob_limit_is_exceeded_in_two_updates() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(block_info.update(gas, blobs, constraints).is_ok());

        let gas = 10;
        let blobs = 13;
        let constraints = 1;
        let err = block_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, BlockInfoError::BlobLimit { available: 10, required: blobs });
    }

    #[test]
    fn update_block_info_fails_if_constraint_limit_is_exceeded() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 7;
        let err = block_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(
            err,
            BlockInfoError::ConstraintLimit { available: constraint_limit, required: constraints }
        );
    }

    #[test]
    fn update_block_info_fails_if_constraint_limit_is_exceeded_in_two_updates() {
        let gas_limit = 100;
        let blob_limit = 12;
        let constraint_limit = 5;
        let mut block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);

        let gas = 10;
        let blobs = 2;
        let constraints = 1;
        assert!(block_info.update(gas, blobs, constraints).is_ok());

        let gas = 10;
        let blobs = 2;
        let constraints = 7;
        let err = block_info.update(gas, blobs, constraints).unwrap_err();
        assert_eq!(err, BlockInfoError::ConstraintLimit { available: 4, required: constraints });
    }
}
