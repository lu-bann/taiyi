use std::{any::type_name, fmt::Debug};

use bincode::{decode_from_slice, encode_to_vec, Decode, Encode};
use redb::{TypeName, Value};

#[derive(Debug, Clone, Decode, Encode, PartialEq)]
pub struct PreconfRequestData {
    pub preconf_type: u8,                  // 0: Type A, 1: Type B
    pub preconf_request: String,           // Serde json string
    pub preconf_request_signature: String, // Hex encoded signature
}

/// Wrapper type to handle values using bincode serialization
#[derive(Debug)]
pub struct Bincode<T>(pub T);

impl<T> Value for Bincode<T>
where
    T: Debug + Encode + Decode<()>,
{
    type SelfType<'a>
        = T
    where
        Self: 'a;

    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        decode_from_slice(data, bincode::config::standard()).expect("Failed to decode bincode").0
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        encode_to_vec(value, bincode::config::standard()).expect("Failed to encode bincode")
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("Bincode<{}>", type_name::<T>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Decode, Encode)]
    struct TestStruct {
        id: u64,
        name: String,
        data: Vec<u8>,
    }

    #[test]
    fn test_bincode_roundtrip() {
        // Create test values of different types
        let test_string = String::from("Hello, world!");
        let test_int = 42u64;
        let test_struct = TestStruct { id: 1, name: "Test".to_string(), data: vec![1, 2, 3, 4, 5] };

        // Test string roundtrip
        let bytes = <Bincode<String>>::as_bytes(&test_string);
        let decoded = <Bincode<String>>::from_bytes(&bytes);
        assert_eq!(decoded, test_string);

        // Test integer roundtrip
        let bytes = <Bincode<u64>>::as_bytes(&test_int);
        let decoded = <Bincode<u64>>::from_bytes(&bytes);
        assert_eq!(decoded, test_int);

        // Test struct roundtrip
        let bytes = <Bincode<TestStruct>>::as_bytes(&test_struct);
        let decoded = <Bincode<TestStruct>>::from_bytes(&bytes);
        assert_eq!(decoded, test_struct);
    }

    #[test]
    fn test_bincode_type_name() {
        assert_eq!(
            <Bincode<String>>::type_name(),
            TypeName::new(&format!("Bincode<{}>", type_name::<String>()))
        );
        assert_eq!(
            <Bincode<u64>>::type_name(),
            TypeName::new(&format!("Bincode<{}>", type_name::<u64>()))
        );
        assert_eq!(
            <Bincode<TestStruct>>::type_name(),
            TypeName::new(&format!("Bincode<{}>", type_name::<TestStruct>()))
        );
    }

    #[test]
    fn test_bincode_fixed_width() {
        assert_eq!(<Bincode<String>>::fixed_width(), None);
        assert_eq!(<Bincode<u64>>::fixed_width(), None);
        assert_eq!(<Bincode<TestStruct>>::fixed_width(), None);
    }

    #[test]
    fn test_preconf_request_data_serialization() {
        let original = PreconfRequestData {
            preconf_type: 1,
            preconf_request: r#"{"key": "value"}"#.to_string(),
            preconf_request_signature: "abcdef1234567890".to_string(),
        };

        // Serialize and deserialize using Bincode
        let bytes = <Bincode<PreconfRequestData>>::as_bytes(&original);
        let decoded = <Bincode<PreconfRequestData>>::from_bytes(&bytes);

        assert_eq!(decoded, original);
    }

    #[test]
    fn test_bincode_with_vector_of_preconf_data() {
        // Create a vector of PreconfRequestData
        let data_vec = vec![
            PreconfRequestData {
                preconf_type: 0,
                preconf_request: r#"{"key": "value"}"#.to_string(),
                preconf_request_signature: "signature1".to_string(),
            },
            PreconfRequestData {
                preconf_type: 1,
                preconf_request: r#"{"key": "value"}"#.to_string(),
                preconf_request_signature: "signature2".to_string(),
            },
            PreconfRequestData {
                preconf_type: 0,
                preconf_request: r#"{"key": "value"}"#.to_string(),
                preconf_request_signature: "signature3".to_string(),
            },
        ];

        // Test serialization and deserialization of the vector
        let bytes = <Bincode<Vec<PreconfRequestData>>>::as_bytes(&data_vec);
        let decoded = <Bincode<Vec<PreconfRequestData>>>::from_bytes(&bytes);

        assert_eq!(decoded.len(), data_vec.len());
        assert_eq!(decoded, data_vec);
    }

    #[test]
    fn test_bincode_with_empty_vector_of_preconf_data() {
        // Test with an empty vector
        let empty_vec: Vec<PreconfRequestData> = vec![];

        let bytes = <Bincode<Vec<PreconfRequestData>>>::as_bytes(&empty_vec);
        let decoded = <Bincode<Vec<PreconfRequestData>>>::from_bytes(&bytes);

        assert_eq!(decoded.len(), 0);
        assert!(decoded.is_empty());
    }

    #[test]
    #[should_panic(expected = "Failed to decode bincode")]
    fn test_bincode_decode_invalid_data() {
        // Test decoding invalid data
        let invalid_data = "invalid data"; // Invalid data that can't be decoded
        <Bincode<String>>::from_bytes(invalid_data.as_bytes()); // This should panic
    }
}
