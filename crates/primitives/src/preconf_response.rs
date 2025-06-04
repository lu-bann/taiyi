use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfResponseData {
    pub request_id: Uuid,
    pub commitment: Option<String>,
    pub sequence_num: Option<u64>,
    /// current slot at the time of response
    pub current_slot: u64,
}

impl PreconfResponseData {
    pub fn success(
        request_id: Uuid,
        commitment: Option<String>,
        sequence_num: Option<u64>,
        current_slot: u64,
    ) -> Self {
        PreconfResponseData { request_id, commitment, sequence_num, current_slot }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_preconf_response_success_trivial() {
        let request_id = Uuid::new_v4();
        let commitment = Some("commitment_string".to_string());
        let sequence_num = Some(42);
        let current_slot = 100;

        let data = PreconfResponseData::success(
            request_id,
            commitment.clone(),
            sequence_num,
            current_slot,
        );

        assert_eq!(
            data,
            PreconfResponseData { request_id, commitment, sequence_num, current_slot }
        );
    }
    #[test]
    fn test_preconf_response_data_serde() {
        let data = PreconfResponseData::success(
            Uuid::new_v4(),
            Some("commitment_string".to_string()),
            Some(42),
            100,
        );

        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: PreconfResponseData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(data, deserialized);
    }
}
