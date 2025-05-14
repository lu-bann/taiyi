// This file is copied from https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/map_fp_to_g1.rs
// Constants related to the bls12-381 precompile inputs and outputs
#![allow(dead_code)]
/// FP_LENGTH specifies the number of bytes needed to represent an
/// Fp element. This is an element in the base field of BLS12-381.
///
/// Note: The base field is used to define G1 and G2 elements.
pub const FP_LENGTH: usize = 48;
/// PADDED_FP_LENGTH specifies the number of bytes that the EVM will use
/// to represent an Fp element according to EIP-2537.
///
/// Note: We only need FP_LENGTH number of bytes to represent it,
/// but we pad the byte representation to be 32 byte aligned as specified in EIP 2537.
pub const PADDED_FP_LENGTH: usize = 64;

/// G1_LENGTH specifies the number of bytes needed to represent a G1 element.
///
/// Note: A G1 element contains 2 Fp elements.
pub const G1_LENGTH: usize = 2 * FP_LENGTH;
/// PADDED_G1_LENGTH specifies the number of bytes that the EVM will use to represent
/// a G1 element according to padding rules specified in EIP-2537.
pub const PADDED_G1_LENGTH: usize = 2 * PADDED_FP_LENGTH;

/// PADDED_FP2_LENGTH specifies the number of bytes that the EVM will use to represent
/// a Fp^2 element according to the padding rules specified in EIP-2537.
///
/// Note: This is the quadratic extension of Fp, and by definition
/// means we need 2 Fp elements.
pub const PADDED_FP2_LENGTH: usize = 2 * PADDED_FP_LENGTH;

/// SCALAR_LENGTH specifies the number of bytes needed to represent an Fr element.
/// This is an element in the scalar field of BLS12-381.
///
/// Note: Since it is already 32 byte aligned, there is no padded version of this constant.
pub const SCALAR_LENGTH: usize = 32;
/// SCALAR_LENGTH_BITS specifies the number of bits needed to represent an Fr element.
/// This is an element in the scalar field of BLS12-381.
pub const SCALAR_LENGTH_BITS: usize = SCALAR_LENGTH * 8;

/// G1_ADD_INPUT_LENGTH specifies the number of bytes that the input to G1ADD
/// must use.
///
/// Note: The input to the G1 addition precompile is 2 G1 elements.
pub const G1_ADD_INPUT_LENGTH: usize = 2 * PADDED_G1_LENGTH;
/// G1_MSM_INPUT_LENGTH specifies the number of bytes that each MSM input pair should have.
///
/// Note: An MSM pair is a G1 element and a scalar. The input to the MSM precompile will have `n`
/// of these pairs.
pub const G1_MSM_INPUT_LENGTH: usize = PADDED_G1_LENGTH + SCALAR_LENGTH;

/// PADDED_G2_LENGTH specifies the number of bytes that the EVM will use to represent
/// a G2 element.
///
/// Note: A G2 element can be represented using 2 Fp^2 elements.
pub const PADDED_G2_LENGTH: usize = 2 * PADDED_FP2_LENGTH;

/// G2_ADD_INPUT_LENGTH specifies the number of bytes that the input to G2ADD
/// must occupy.
///
/// Note: The input to the G2 addition precompile is 2 G2 elements.
pub const G2_ADD_INPUT_LENGTH: usize = 2 * PADDED_G2_LENGTH;
/// G2_MSM_INPUT_LENGTH specifies the number of bytes that each MSM input pair should have.
///
/// Note: An MSM pair is a G2 element and a scalar. The input to the MSM will have `n`
/// of these pairs.
pub const G2_MSM_INPUT_LENGTH: usize = PADDED_G2_LENGTH + SCALAR_LENGTH;

/// PAIRING_INPUT_LENGTH specifies the number of bytes that each Pairing input pair should have.
///
/// Note: An Pairing input-pair is a G2 element and a G1 element. The input to the Pairing will have `n`
/// of these pairs.
pub const PAIRING_INPUT_LENGTH: usize = PADDED_G1_LENGTH + PADDED_G2_LENGTH;

/// FP_PAD_BY specifies the number of bytes that an FP_ELEMENT is padded by to make it 32 byte aligned.
///
/// Note: This should be equal to PADDED_FP_LENGTH - FP_LENGTH.
pub const FP_PAD_BY: usize = 16;
