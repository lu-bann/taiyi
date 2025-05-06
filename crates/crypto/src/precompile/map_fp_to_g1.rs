/// This file is copied from https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/map_fp_to_g1.rs
use alloy_primitives::Bytes;

use super::{
    blst_utils::{encode_g1_point, map_fp_to_g1 as blst_map_fp_to_g1, read_fp},
    constant::PADDED_FP_LENGTH,
    error::PrecompileError,
    utils::remove_fp_padding,
};

/// Field-to-curve call expects 64 bytes as an input that is interpreted as an
/// element of Fp. Output of this call is 128 bytes and is an encoded G1 point.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp-element-to-g1-point>
pub fn map_fp_to_g1(input: &Bytes) -> Result<Bytes, PrecompileError> {
    if input.len() != PADDED_FP_LENGTH {
        return Err(PrecompileError::Other(format!(
            "MAP_FP_TO_G1 input should be {PADDED_FP_LENGTH} bytes, was {}",
            input.len()
        )));
    }

    let input_p0 = remove_fp_padding(input)?;
    let fp = read_fp(input_p0)?;
    let p_aff = blst_map_fp_to_g1(&fp);

    let out = encode_g1_point(&p_aff);
    Ok(out.into())
}
