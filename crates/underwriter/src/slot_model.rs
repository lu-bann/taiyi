use std::time::Duration;

use alloy_eips::merge::{EPOCH_DURATION, SLOT_DURATION};

#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub epoch: u64,
    pub slot: u64,
}

impl Slot {
    pub const fn new(epoch: u64, slot: u64) -> Self {
        Self { epoch, slot }
    }
}

pub const HOLESKY_GENESIS_TIMESTAMP: u64 = 1_695_902_400;

#[derive(Debug, Clone)]
pub struct SlotModel {
    pub genesis_epoch_offset: Duration,
    pub slot_duration: Duration,
    pub epoch_duration: Duration,
}

impl SlotModel {
    pub const fn new(
        genesis_epoch_offset: Duration,
        slot_duration: Duration,
        epoch_duration: Duration,
    ) -> Self {
        Self { genesis_epoch_offset, slot_duration, epoch_duration }
    }

    pub const fn holesky() -> Self {
        Self::new(Duration::from_secs(HOLESKY_GENESIS_TIMESTAMP), SLOT_DURATION, EPOCH_DURATION)
    }

    pub fn get_slot(&self, time_since_epoch: Duration) -> Slot {
        let time_since_genesis = (time_since_epoch - self.genesis_epoch_offset).as_secs();
        Slot {
            epoch: time_since_genesis / self.epoch_duration.as_secs(),
            slot: (time_since_genesis % self.epoch_duration.as_secs())
                / self.slot_duration.as_secs(),
        }
    }

    pub fn get_timestamp(&self, slot: u64) -> u64 {
        self.genesis_epoch_offset.as_secs() + self.slot_duration.as_secs() * slot
    }

    pub fn get_slot_number(&self, slot: Slot) -> u64 {
        slot.epoch * self.slots_per_epoch() + slot.slot
    }

    pub fn slots_per_epoch(&self) -> u64 {
        self.epoch_duration.as_secs() / self.slot_duration.as_secs()
    }

    pub fn get_time_until_next_slot_start(&self, now_since_epoch: Duration) -> Duration {
        let now_since_genesis = now_since_epoch - self.genesis_epoch_offset;
        let passed_slots = now_since_genesis.as_secs() / self.slot_duration.as_secs();
        self.genesis_epoch_offset + self.slot_duration * (passed_slots + 1) as u32
    }

    pub fn get_next_slot_start_offset(&self, slot: u64) -> Duration {
        self.genesis_epoch_offset + self.slot_duration * (slot + 1) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENESIS_TIMESTAMP: u64 = 12345;
    const TEST_SLOT_DURATION: Duration = Duration::from_secs(10);
    const TEST_EPOCH_DURATION: Duration = Duration::from_secs(50);

    #[test]
    fn slot_model_get_timestamp_for_slot_0() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let ts = model.get_timestamp(0);
        assert_eq!(ts, TEST_GENESIS_TIMESTAMP);
    }

    #[test]
    fn slot_model_get_timestamp_for_slot_3() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let ts = model.get_timestamp(3);
        assert_eq!(ts, TEST_GENESIS_TIMESTAMP + TEST_SLOT_DURATION.as_secs() * 3);
    }

    #[test]
    fn slots_per_epoch() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slots_per_epoch = model.slots_per_epoch();
        assert_eq!(slots_per_epoch, 5);
    }

    #[test]
    fn get_total_slot_number_from_slot() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let epoch = 10;
        let slot = 3;
        let slot = Slot::new(epoch, slot);
        let slot_number = model.get_slot_number(slot);
        assert_eq!(slot_number, 53);
    }

    #[test]
    fn slot_model_epoch_0_slot_0() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(TEST_GENESIS_TIMESTAMP);
        assert_eq!(slot, Slot::new(0, 0));
    }

    #[test]
    fn slot_model_epoch_0_slot_0_inexact() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(TEST_GENESIS_TIMESTAMP + TEST_SLOT_DURATION.as_secs() / 2);
        assert_eq!(slot, Slot::new(0, 0));
    }

    #[test]
    fn slot_model_epoch_1_slot_0() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(TEST_GENESIS_TIMESTAMP + TEST_EPOCH_DURATION.as_secs());
        assert_eq!(slot, Slot::new(1, 0));
    }

    #[test]
    fn slot_model_epoch_1_slot_3() {
        let model = SlotModel::new(TEST_GENESIS_TIMESTAMP, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(
            TEST_GENESIS_TIMESTAMP
                + TEST_EPOCH_DURATION.as_secs()
                + 3 * TEST_SLOT_DURATION.as_secs(),
        );
        assert_eq!(slot, Slot::new(1, 3));
    }
}
