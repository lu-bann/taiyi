use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct SequenceNumberPerSlot {
    sequence_numbers: HashMap<u64, u64>,
}

impl SequenceNumberPerSlot {
    pub fn new() -> Self {
        Self { sequence_numbers: HashMap::new() }
    }

    pub fn get_next(&self, slot: u64) -> u64 {
        self.sequence_numbers.get(&slot).cloned().unwrap_or_default() + 1
    }

    pub fn add(&mut self, slot: u64, offset: u64) {
        *self.sequence_numbers.entry(slot).or_default() += offset;
    }

    pub fn get_next_and_add(&mut self, slot: u64, offset: u64) -> u64 {
        let next = self.get_next(slot);
        self.add(slot, offset);
        next
    }

    #[allow(dead_code)]
    pub fn remove_before(&mut self, first_slot_to_keep: u64) {
        self.sequence_numbers.retain(|k, _| *k >= first_slot_to_keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_next_initially_returns_1() {
        let sequence_number = SequenceNumberPerSlot::new();
        let slot = 0u64;
        assert_eq!(sequence_number.get_next(slot), 1u64);
        let slot = 11u64;
        assert_eq!(sequence_number.get_next(slot), 1u64);
    }

    #[test]
    fn test_add() {
        let mut sequence_number = SequenceNumberPerSlot::new();
        let slot1 = 0u64;
        assert_eq!(sequence_number.get_next(slot1), 1u64);
        let slot2 = 11u64;
        assert_eq!(sequence_number.get_next(slot2), 1u64);

        let offset = 3;
        sequence_number.add(slot2, offset);

        assert_eq!(sequence_number.get_next(slot1), 1u64);
        assert_eq!(sequence_number.get_next(slot2), 4u64);
    }

    #[test]
    fn test_get_next_and_add() {
        let mut sequence_number = SequenceNumberPerSlot::new();
        let slot1 = 0u64;
        let offset = 1u64;
        assert_eq!(sequence_number.get_next_and_add(slot1, offset), 1u64);
        let slot2 = 11u64;
        let offset = 3u64;
        assert_eq!(sequence_number.get_next_and_add(slot2, offset), 1u64);

        assert_eq!(sequence_number.get_next(slot1), 2u64);
        assert_eq!(sequence_number.get_next(slot2), 4u64);
    }

    #[test]
    fn test_remove_until() {
        let mut sequence_number = SequenceNumberPerSlot::new();
        let slot1 = 10u64;
        let offset = 1u64;
        assert_eq!(sequence_number.get_next_and_add(slot1, offset), 1u64);
        let slot2 = 11u64;
        let offset = 3u64;
        assert_eq!(sequence_number.get_next_and_add(slot2, offset), 1u64);

        assert_eq!(sequence_number.get_next(slot1), 2u64);
        assert_eq!(sequence_number.get_next(slot2), 4u64);

        let first_slot_to_keep = 11u64;
        sequence_number.remove_before(first_slot_to_keep);

        assert_eq!(sequence_number.get_next(slot1), 1u64);
        assert_eq!(sequence_number.get_next(slot2), 4u64);
    }
}
