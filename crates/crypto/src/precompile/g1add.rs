/// This file is copied from https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/g1_add.rs
use alloy_primitives::Bytes;

use crate::precompile::constant::G1_ADD_INPUT_LENGTH;

use super::{
    blst_utils::{encode_g1_point, p1_add_affine, read_g1_no_subgroup_check},
    constant::PADDED_G1_LENGTH,
    error::PrecompileError,
    utils::remove_g1_padding,
};

pub fn g1_add(input: &Bytes) -> Result<Bytes, PrecompileError> {
    if input.len() != G1_ADD_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G1ADD input should be {G1_ADD_INPUT_LENGTH} bytes, was {}",
            input.len()
        )));
    }

    let [a_x, a_y] = remove_g1_padding(&input[..PADDED_G1_LENGTH])?;
    let [b_x, b_y] = remove_g1_padding(&input[PADDED_G1_LENGTH..])?;

    // NB: There is no subgroup check for the G1 addition precompile because the time to do the subgroup
    // check would be more than the time it takes to to do the g1 addition.
    //
    // Users should be careful to note whether the points being added are indeed in the right subgroup.
    let a_aff = &read_g1_no_subgroup_check(a_x, a_y)?;
    let b_aff = &read_g1_no_subgroup_check(b_x, b_y)?;
    let p_aff = p1_add_affine(a_aff, b_aff);

    let out = encode_g1_point(&p_aff);
    Ok(out.into())
}
