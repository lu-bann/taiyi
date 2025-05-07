// This file is copied from https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/pairing.rs
use alloy_primitives::{Bytes, B256};

use super::{
    blst_utils::{pairing_check, read_g1, read_g2},
    constant::{PADDED_G1_LENGTH, PADDED_G2_LENGTH, PAIRING_INPUT_LENGTH},
    error::PrecompileError,
    utils::{remove_g1_padding, remove_g2_padding},
};

/// Pairing call expects 384*k (k being a positive integer) bytes as an inputs
/// that is interpreted as byte concatenation of k slices. Each slice has the
/// following structure:
///    * 128 bytes of G1 point encoding
///    * 256 bytes of G2 point encoding
///
/// Each point is expected to be in the subgroup of order q.
/// Output is 32 bytes where first 31 bytes are equal to 0x00 and the last byte
/// is 0x01 if pairing result is equal to the multiplicative identity in a pairing
/// target field and 0x00 otherwise.
///
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing>
#[allow(unused)]
pub fn pairing(input: &Bytes) -> Result<Bytes, PrecompileError> {
    let input_len = input.len();
    if input_len == 0 || input_len % PAIRING_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(format!(
            "Pairing input length should be multiple of {PAIRING_INPUT_LENGTH}, was {input_len}"
        )));
    }

    let k = input_len / PAIRING_INPUT_LENGTH;

    // Collect pairs of points for the pairing check
    let mut pairs = Vec::with_capacity(k);
    for i in 0..k {
        let encoded_g1_element =
            &input[i * PAIRING_INPUT_LENGTH..i * PAIRING_INPUT_LENGTH + PADDED_G1_LENGTH];
        let encoded_g2_element = &input[i * PAIRING_INPUT_LENGTH + PADDED_G1_LENGTH
            ..i * PAIRING_INPUT_LENGTH + PADDED_G1_LENGTH + PADDED_G2_LENGTH];

        // If either the G1 or G2 element is the encoded representation
        // of the point at infinity, then these two points are no-ops
        // in the pairing computation.
        //
        // Note: we do not skip the validation of these two elements even if
        // one of them is the point at infinity because we could have G1 be
        // the point at infinity and G2 be an invalid element or vice versa.
        // In that case, the precompile should error because one of the elements
        // was invalid.
        let g1_is_zero = encoded_g1_element.iter().all(|i| *i == 0);
        let g2_is_zero = encoded_g2_element.iter().all(|i| *i == 0);

        let [a_x, a_y] = remove_g1_padding(encoded_g1_element)?;
        let [b_x_0, b_x_1, b_y_0, b_y_1] = remove_g2_padding(encoded_g2_element)?;

        // NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
        // extract_g1_input and extract_g2_input perform the necessary checks
        let p1_aff = read_g1(a_x, a_y)?;
        let p2_aff = read_g2(b_x_0, b_x_1, b_y_0, b_y_1)?;

        if !g1_is_zero & !g2_is_zero {
            pairs.push((p1_aff, p2_aff));
        }
    }
    let result = if pairing_check(&pairs) { 1 } else { 0 };

    Ok(B256::with_last_byte(result).into())
}
