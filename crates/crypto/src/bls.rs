use std::default;

use blst::{
    blst_fp, blst_fp2, blst_p1, blst_p1_add_affine, blst_p1_affine, blst_p2, blst_p2_affine,
};

#[derive(Debug, Default)]
pub struct Fp {
    inner: blst_fp,
}

#[derive(Debug, Default)]
pub struct Fp2 {
    inner: blst_fp2,
}

#[derive(Debug, Default)]
pub struct G1Point {
    x: Fp,
    y: Fp,
    inner: blst_p1_affine,
}

#[derive(Debug, Default)]
pub struct G2Point {
    x: Fp2,
    y: Fp2,
    inner: blst_p2_affine,
}

pub fn G1_add(a: G1Point, b: G1Point) -> G1Point {
    let mut out = G1Point::default();
    unsafe {
        blst_p1_add_affine(&mut out.inner, &a.inner, &b.inner);
    }
    out
}
