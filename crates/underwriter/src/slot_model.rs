use std::time::Duration;

#[derive(Debug, PartialEq)]
pub struct Slot {
    pub epoch: u64,
    pub slot: u64,
}

impl Slot {
    pub const fn new(epoch: u64, slot: u64) -> Self {
        Self { epoch, slot }
    }
}

#[derive(Debug, Clone)]
pub struct SlotModel {
    genesis_epoch_offset: Duration,
    slot_duration: Duration,
    epoch_duration: Duration,
}

impl SlotModel {
    pub const fn new(
        genesis_epoch_offset: Duration,
        slot_duration: Duration,
        epoch_duration: Duration,
    ) -> Self {
        Self { genesis_epoch_offset, slot_duration, epoch_duration }
    }

    pub fn get_slot(&self, now_since_epoch: Duration) -> Slot {
        let now_since_genesis = now_since_epoch - self.genesis_epoch_offset;
        Slot {
            epoch: now_since_genesis.as_secs() / self.epoch_duration.as_secs(),
            slot: (now_since_genesis.as_secs() % self.epoch_duration.as_secs())
                / self.slot_duration.as_secs(),
        }
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

    const TEST_GENESIS_DURATION: Duration = Duration::from_secs(12345);
    const TEST_SLOT_DURATION: Duration = Duration::from_secs(10);
    const TEST_EPOCH_DURATION: Duration = Duration::from_secs(50);

    #[test]
    fn slot_model_epoch_0_slot_0() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(TEST_GENESIS_DURATION);
        assert_eq!(slot, Slot::new(0, 0));
    }

    #[test]
    fn slot_model_epoch_0_slot_0_inexact() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(TEST_GENESIS_DURATION + TEST_SLOT_DURATION / 2);
        assert_eq!(slot, Slot::new(0, 0));
    }

    #[test]
    fn slot_model_epoch_1_slot_0() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = model.get_slot(TEST_GENESIS_DURATION + TEST_EPOCH_DURATION);
        assert_eq!(slot, Slot::new(1, 0));
    }

    #[test]
    fn slot_model_epoch_1_slot_3() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot =
            model.get_slot(TEST_GENESIS_DURATION + TEST_EPOCH_DURATION + 3 * TEST_SLOT_DURATION);
        assert_eq!(slot, Slot::new(1, 3));
    }

    #[test]
    fn get_next_slot_start_at_genesis() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let now_since_epoch = TEST_GENESIS_DURATION;
        let next_slot_start = model.get_time_until_next_slot_start(now_since_epoch);
        assert_eq!(next_slot_start, TEST_GENESIS_DURATION + TEST_SLOT_DURATION);
    }

    #[test]
    fn get_next_slot_start_half_slot_after_genesis() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let now_since_epoch = TEST_GENESIS_DURATION + TEST_SLOT_DURATION / 2;
        let next_slot_start = model.get_time_until_next_slot_start(now_since_epoch);
        assert_eq!(next_slot_start, TEST_GENESIS_DURATION + TEST_SLOT_DURATION);
    }

    #[test]
    fn get_next_slot_start_three_slots_after_genesis() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let now_since_epoch = TEST_GENESIS_DURATION + TEST_SLOT_DURATION * 3;
        let next_slot_start = model.get_time_until_next_slot_start(now_since_epoch);
        assert_eq!(next_slot_start, TEST_GENESIS_DURATION + TEST_SLOT_DURATION * 4);
    }

    #[test]
    fn get_next_slot_start_epoch_offset_at_genesis() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = 0;
        let next_slot_start_offset = model.get_next_slot_start_offset(slot);
        assert_eq!(next_slot_start_offset, TEST_GENESIS_DURATION + TEST_SLOT_DURATION);
    }

    #[test]
    fn get_next_slot_start_epoch_offset_at_ten_slots_after_genesis() {
        let model = SlotModel::new(TEST_GENESIS_DURATION, TEST_SLOT_DURATION, TEST_EPOCH_DURATION);

        let slot = 10;
        let next_slot_start_offset = model.get_next_slot_start_offset(slot);
        assert_eq!(next_slot_start_offset, TEST_GENESIS_DURATION + 11 * TEST_SLOT_DURATION);
    }
}
