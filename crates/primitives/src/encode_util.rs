use alloy_signer::k256::ecdsa::SigningKey;
use hex::{decode, encode, FromHexError};

pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", encode(data))
}

pub fn hex_decode(hex_string: &str) -> Result<Vec<u8>, FromHexError> {
    decode(hex_string.trim_start_matches("0x"))
}

pub fn hex_to_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
}

pub fn u64_to_hex(value: u64) -> String {
    format!("{:#x}", value)
}

pub fn get_signing_key(private_key: &str) -> eyre::Result<SigningKey> {
    let pkey_bytes = hex_decode(private_key)?;
    Ok(SigningKey::from_slice(&pkey_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        let encoded = hex_encode([15u8]);
        assert_eq!(encoded, String::from("0x0f"));
    }

    #[test]
    fn test_hex_decode() {
        let hex_str = "0x10";
        let decoded = hex_decode(hex_str).unwrap();
        assert_eq!(decoded, vec![16u8]);
    }

    #[test]
    fn test_hex_to_u64() {
        let hex_str = "0x10";
        let decoded = hex_to_u64(hex_str).unwrap();
        assert_eq!(decoded, 16u64);
    }

    #[test]
    fn test_u64_to_hex() {
        let value = 16u64;
        let encoded = u64_to_hex(value);
        assert_eq!(encoded, "0x10");
    }
}
