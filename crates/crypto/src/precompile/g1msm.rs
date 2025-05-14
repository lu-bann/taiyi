// This file is copied from https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/g1_msm.rs
use alloy_primitives::Bytes;

use super::error::PrecompileError;
use crate::precompile::{
    blst_utils::{encode_g1_point, p1_msm, read_g1, read_scalar},
    constant::{G1_MSM_INPUT_LENGTH, PADDED_G1_LENGTH, SCALAR_LENGTH},
    utils::remove_g1_padding,
};

/// Implements EIP-2537 G1MSM precompile.
/// G1 multi-scalar-multiplication call expects `160*k` bytes as an input that is interpreted
/// as byte concatenation of `k` slices each of them being a byte concatenation
/// of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32`
/// bytes).
/// Output is an encoding of multi-scalar-multiplication operation result - single G1
/// point (`128` bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-multiexponentiation>
pub fn g1_msm(input: &Bytes) -> Result<Bytes, PrecompileError> {
    let input_len = input.len();
    if input_len == 0 || input_len % G1_MSM_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(format!(
            "G1MSM input length should be multiple of {}, was {}",
            G1_MSM_INPUT_LENGTH, input_len
        )));
    }

    let k = input_len / G1_MSM_INPUT_LENGTH;

    let mut g1_points: Vec<_> = Vec::with_capacity(k);
    let mut scalars = Vec::with_capacity(k);
    for i in 0..k {
        let encoded_g1_element =
            &input[i * G1_MSM_INPUT_LENGTH..i * G1_MSM_INPUT_LENGTH + PADDED_G1_LENGTH];
        let encoded_scalar = &input[i * G1_MSM_INPUT_LENGTH + PADDED_G1_LENGTH
            ..i * G1_MSM_INPUT_LENGTH + PADDED_G1_LENGTH + SCALAR_LENGTH];

        // Filter out points infinity as an optimization, since it is a no-op.
        // Note: Previously, points were being batch converted from Jacobian to Affine.
        // In `blst`, this would essentially, zero out all of the points.
        // Since all points are now in affine, this bug is avoided.
        if encoded_g1_element.iter().all(|i| *i == 0) {
            continue;
        }

        let [a_x, a_y] = remove_g1_padding(encoded_g1_element)?;

        // NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
        let p0_aff = read_g1(a_x, a_y)?;

        // If the scalar is zero, then this is a no-op.
        //
        // Note: This check is made after checking that g1 is valid.
        // this is because we want the precompile to error when
        // G1 is invalid, even if the scalar is zero.
        if encoded_scalar.iter().all(|i| *i == 0) {
            continue;
        }

        g1_points.push(p0_aff);
        scalars.push(read_scalar(encoded_scalar)?);
    }

    // Return the encoding for the point at the infinity according to EIP-2537
    // if there are no points in the MSM.
    const ENCODED_POINT_AT_INFINITY: [u8; PADDED_G1_LENGTH] = [0; PADDED_G1_LENGTH];
    if g1_points.is_empty() {
        return Ok(ENCODED_POINT_AT_INFINITY.into());
    }

    let multiexp_aff = p1_msm(g1_points, scalars);

    let out = encode_g1_point(&multiexp_aff);
    Ok(out.into())
}
