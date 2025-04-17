use ethereum_consensus::deneb::Context;

pub const SET_CONSTRAINTS_CUTOFF_S: u64 = 8;
pub const SET_CONSTRAINTS_CUTOFF_DELTA_S: u64 = 1;

pub trait ContextExt {
    /// Get the deadline timestamp of a slot for submitting constraints.
    fn get_deadline_of_slot(&self, slot: u64) -> u64;

    fn actual_genesis_time(&self) -> u64;
}

impl ContextExt for Context {
    fn get_deadline_of_slot(&self, slot: u64) -> u64 {
        let genesis_time = self.actual_genesis_time();
        genesis_time + ((slot - 1) * self.seconds_per_slot) + SET_CONSTRAINTS_CUTOFF_S
            - SET_CONSTRAINTS_CUTOFF_DELTA_S
    }

    fn actual_genesis_time(&self) -> u64 {
        match self.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.min_genesis_time + self.genesis_delay,
        }
    }
}
