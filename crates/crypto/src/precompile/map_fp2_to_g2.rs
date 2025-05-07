// This file is copied from https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/map_fp2_to_g2.rs
use alloy_primitives::Bytes;

use super::{
    blst_utils::{encode_g2_point, map_fp2_to_g2 as blst_map_fp2_to_g2, read_fp2},
    constant::{PADDED_FP2_LENGTH, PADDED_FP_LENGTH},
    error::PrecompileError,
    utils::remove_fp_padding,
};

/// Field-to-curve call expects 128 bytes as an input that is interpreted as
/// an element of Fp2. Output of this call is 256 bytes and is an encoded G2
/// point.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp2-element-to-g2-point>
pub fn map_fp2_to_g2(input: &Bytes) -> Result<Bytes, PrecompileError> {
    if input.len() != PADDED_FP2_LENGTH {
        return Err(PrecompileError::Other(format!(
            "MAP_FP2_TO_G2 input should be {PADDED_FP2_LENGTH} bytes, was {}",
            input.len()
        )));
    }

    let input_p0_x = remove_fp_padding(&input[..PADDED_FP_LENGTH])?;
    let input_p0_y = remove_fp_padding(&input[PADDED_FP_LENGTH..PADDED_FP2_LENGTH])?;
    let fp2 = read_fp2(input_p0_x, input_p0_y)?;
    let p_aff = blst_map_fp2_to_g2(&fp2);

    let out = encode_g2_point(&p_aff);
    Ok(out.into())
}
