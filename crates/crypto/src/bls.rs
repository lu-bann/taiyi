#![allow(unused)]
use alloy::primitives::{keccak256, Bytes, U256};
use alloy::sol_types::{sol, SolValue};
use taiyi_contracts::{Fp, Fp2, G1Point, G2Point};

use crate::precompile::{
    g1_msm, g2_msm as g2_mul_precompile, map_fp2_to_g2 as map_fp2_to_g2_precompile,
};

pub fn sign(sk: U256, msg: &[u8], domain_separator: &[u8]) -> eyre::Result<G2Point> {
    let fp2 = to_message_point(msg, domain_separator);
    let g2 = map_fp2_to_g2(fp2)?;
    let g2_mul = g2_mul(g2, sk)?;
    Ok(g2_mul)
}

pub fn to_message_point(msg: &[u8], domain_separator: &[u8]) -> Fp2 {
    let mut msg_prime = domain_separator.to_vec();
    msg_prime.extend(msg);
    let hashed = keccak256(msg_prime);
    let yy = U256::from_be_slice(hashed.as_ref());
    Fp2 { c0: Fp { a: U256::from(0), b: U256::from(0) }, c1: Fp { a: U256::from(0), b: yy } }
}

pub fn map_fp2_to_g2(fp2: Fp2) -> eyre::Result<G2Point> {
    let input = fp2.abi_encode_sequence();
    let input_bytes = Bytes::from(input);
    let output = map_fp2_to_g2_precompile(&input_bytes)?;
    let output_bytes = output.as_ref();
    let output_g2 = G2Point::abi_decode_sequence(output_bytes)?;
    Ok(output_g2)
}

pub fn g2_mul(point: G2Point, scalar: U256) -> eyre::Result<G2Point> {
    let input = (point, scalar).abi_encode_sequence();
    let input_bytes = Bytes::from(input);
    let output = g2_mul_precompile(&input_bytes)?;
    let output_bytes = output.as_ref();
    let output_g2 = G2Point::abi_decode_sequence(output_bytes)?;
    Ok(output_g2)
}

pub fn to_public_key(sk: U256) -> eyre::Result<G1Point> {
    let g1_generator = G1Point {
        x: Fp {
            a: U256::from(31_827_880_280_837_800_241_567_138_048_534_752_271u128),
            b: U256::from_be_slice(&hex_literal::hex!(
                "c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
            )),
        },
        y: Fp {
            a: U256::from(11_568_204_302_792_691_131_076_548_377_920_244_452u128),
            b: U256::from_be_slice(&hex_literal::hex!(
                "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
            )),
        },
    };
    let input = (g1_generator, sk).abi_encode_sequence();
    let input_bytes = Bytes::from(input);
    let output = g1_msm(&input_bytes)?;
    let output_bytes = output.as_ref();
    let output_g1 = G1Point::abi_decode_sequence(output_bytes)?;
    Ok(output_g1)
}

pub type PublicKey = blst::min_pk::PublicKey;
pub type SecretKey = blst::min_pk::SecretKey;
pub type Signature = blst::min_pk::Signature;

pub fn serialize_bls_signature<S: serde::Serializer>(
    sig: &Signature,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(&sig.serialize())
}

pub fn deserialize_bls_signature<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Signature, D::Error> {
    let bytes = <String as serde::Deserialize>::deserialize(deserializer)?;
    Signature::deserialize(bytes.as_ref())
        .map_err(|err| <D::Error as serde::de::Error>::custom(format!("{:?}", err)))
}

pub fn serialize_bls_publickey<S: serde::Serializer>(
    public_key: &PublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(&public_key.serialize())
}

pub fn bls_pubkey_to_alloy(pubkey: &PublicKey) -> alloy::rpc::types::beacon::BlsPublicKey {
    alloy::rpc::types::beacon::BlsPublicKey::from_slice(&pubkey.compress())
}

pub fn bls_signature_to_alloy(signature: &Signature) -> alloy::rpc::types::beacon::BlsSignature {
    alloy::rpc::types::beacon::BlsSignature::from_slice(&signature.compress())
}
