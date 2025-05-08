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
