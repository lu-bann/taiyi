use alloy::eips::eip4844::DATA_GAS_PER_BLOB;
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct PreconfFee {
    pub gas_fee: u128,
    pub blob_gas_fee: u128,
}

impl PreconfFee {
    pub fn compute_tip(&self, gas_limit: u64, blob_count: usize) -> U256 {
        let gas_limit = U256::from(gas_limit);
        let blob_count = U256::from(blob_count);
        let gas_per_blob = U256::from(DATA_GAS_PER_BLOB);
        U256::from(self.gas_fee) * gas_limit
            + U256::from(self.blob_gas_fee) * gas_per_blob * blob_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_tip() {
        let fee = PreconfFee { gas_fee: 10, blob_gas_fee: 3 };
        let gas_limit = 2;
        let blob_count = 1;
        let tip = fee.compute_tip(gas_limit, blob_count).to::<u64>();
        assert_eq!(tip, 20 + 3 * DATA_GAS_PER_BLOB);
    }
}
