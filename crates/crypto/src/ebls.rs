use std::str::FromStr;
use std::{default, ptr};

use alloy_primitives::{keccak256, Address, U256};
use alloy_provider::network::EthereumWallet;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use blst::min_pk::{
    PublicKey as BlsPubleKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use blst::{
    blst_fp, blst_fp2, blst_map_to_g2, blst_p1, blst_p1_affine, blst_p1_affine_compress,
    blst_p1_generator, blst_p1_mult, blst_p1_to_affine, blst_p2, blst_p2_affine,
    blst_p2_affine_serialize, blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine,
};
use ethereum_consensus::crypto::{PublicKey, SecretKey, Signature};
use reqwest::Url;

const MESSAGE: &str = "";
sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct Fp {
        uint256 a;
        uint256 b;
    }
    #[derive(Debug, PartialEq, Eq)]
    struct Fp2 {
        Fp c0;
        Fp c1;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct G1Point {
        Fp x;
        Fp y;
    }
    #[derive(Debug, PartialEq, Eq)]
    struct G2Point {
        Fp2 x;
        Fp2 y;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    interface BLS {
        function verify(
            bytes memory message,
            G2Point memory signature,
            G1Point memory publicKey,
            bytes memory domainSeparator
        ) public view returns (bool);
        function G1_GENERATOR() internal pure returns (G1Point memory);
        function toPublicKey(uint256 privateKey) public view returns (G1Point memory);
        function toMessagePoint(
            bytes memory message,
            bytes memory domainSeparator
        ) public view returns (G2Point memory);
        function toMessagePointHash(
            bytes memory message,
            bytes memory domainSeparator
        )
            public
            view
            returns (Fp2 memory);
        function G1Add(
            G1Point memory a,
            G1Point memory b
        )
            public
            view
            returns (G1Point memory result);
    }
}

mod sol_kit {
    use super::*;
    pub fn bytes_to_fp(data: &[u8]) -> Fp {
        assert!(data.len() == 48, "invalid length");
        let mut a_bytes: [u8; 32] = [0; 32];
        a_bytes[16..].copy_from_slice(&data[0..16]);
        let a = U256::from_be_bytes(a_bytes);
        let b_bytes: [u8; 32] = data[16..].try_into().expect("pubkey format good");
        let b = U256::from_be_bytes(b_bytes);
        Fp { a, b }
    }

    pub fn bytes_to_fp2(data: &[u8]) -> Fp2 {
        assert!(data.len() == 96, "invalid length");
        let c0 = bytes_to_fp(&data[0..32]);
        let c1 = bytes_to_fp(&data[32..64]);
        Fp2 { c0, c1 }
    }

    pub fn pubkey_to_G1Point(pubkey: PublicKey) -> G1Point {
        bytes_to_G1Point(pubkey.to_vec())
    }

    pub fn bytes_to_G1Point(bytes: Vec<u8>) -> G1Point {
        let blst_key = BlsPubleKey::uncompress(&bytes).expect("uncompress pub");
        let bytes = blst_key.serialize();
        let x = bytes_to_fp(&bytes[0..48]);
        let y = bytes_to_fp(&bytes[48..]);
        G1Point { x, y }
    }

    pub fn signature_to_G2Point(sig: Signature) -> G2Point {
        let blst_sig = BlsSignature::uncompress(&sig.to_vec()).expect("uncompress sig");
        let bytes = blst_sig.serialize();
        bytes_to_G2Point(&bytes)
    }

    pub fn bytes_to_G2Point(bytes: &[u8]) -> G2Point {
        let c0 = bytes_to_fp(&bytes[0..48]);
        let c1 = bytes_to_fp(&bytes[48..96]);
        let x = Fp2 { c0, c1 };
        let c0 = bytes_to_fp(&bytes[96..144]);
        let c1 = bytes_to_fp(&bytes[144..192]);
        let y = Fp2 { c0, c1 };
        G2Point { x, y }
    }
}

mod blst_kit {
    use super::*;
    use blst::blst_bendian_from_fp;
    use blst::blst_p2_from_affine as blst_p2_from_affine_impl;
    use blst::blst_scalar;
    use blst::blst_scalar_from_be_bytes;
    pub fn blst_fp2_map_to_blst_p2(value: blst_fp2) -> blst_p2 {
        let mut out = blst_p2::default();
        unsafe {
            blst_map_to_g2(&mut out, &value, ptr::null());
        }
        out
    }

    pub fn blst_fp2_ser(value: blst_fp2) -> [u8; 96] {
        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];
        let mut result = [0u8; 96];
        unsafe {
            blst_bendian_from_fp(out1.as_mut_ptr(), &value.fp[0]);
            blst_bendian_from_fp(out2.as_mut_ptr(), &value.fp[1]);
        }
        result[0..48].copy_from_slice(&out1);
        result[48..96].copy_from_slice(&out2);
        result
    }

    pub fn blst_p2_to_blst_p2_affine(value: blst_p2) -> blst_p2_affine {
        let mut out = blst_p2_affine::default();
        unsafe {
            blst_p2_to_affine(&mut out, &value);
        }
        out
    }

    pub fn blst_p2_from_affine(value: blst_p2_affine) -> blst_p2 {
        let mut out = blst_p2::default();
        unsafe {
            blst_p2_from_affine_impl(&mut out, &value);
        }
        out
    }

    pub fn blst_p2_affine_ser(value: blst_p2_affine) -> Vec<u8> {
        let mut out = [0u8; 192];
        unsafe {
            blst_p2_affine_serialize(out.as_mut_ptr(), &value);
        }
        out.to_vec()
    }
    pub fn u832_to_fp(value_bytes: [u8; 32]) -> blst_fp {
        let mut first_bytes = [0; 8];
        first_bytes.copy_from_slice(&value_bytes[0..8]);
        let mut second_bytes = [0; 8];
        second_bytes.copy_from_slice(&value_bytes[8..16]);
        let mut third_bytes = [0; 8];
        third_bytes.copy_from_slice(&value_bytes[16..24]);
        let mut fourth_bytes = [0; 8];
        fourth_bytes.copy_from_slice(&value_bytes[24..32]);
        let l = [
            0,
            0,
            u64::from_be_bytes(first_bytes),
            u64::from_be_bytes(second_bytes),
            u64::from_be_bytes(third_bytes),
            u64::from_be_bytes(fourth_bytes),
        ];
        blst_fp { l }
    }

    pub fn compress(point: blst_p1) -> Vec<u8> {
        let mut affine = blst_p1_affine::default();
        let mut pk_comp = [0u8; 48];
        unsafe {
            blst_p1_to_affine(&mut affine, &point);
            blst_p1_affine_compress(pk_comp.as_mut_ptr(), &mut affine);
        }
        pk_comp.to_vec()
    }

    pub fn to_public_key(private: [u8; 32]) -> blst_p1 {
        let generator = unsafe { blst_p1_generator() };
        let mut out = blst_p1::default();
        // let mut scalar = blst_scalar::default();
        unsafe {
            // blst_scalar_from_be_bytes(&mut scalar, private.as_ptr(), 32);
            blst_p1_mult(&mut out, generator, private.as_ptr(), 32);
        }
        out
    }
}

fn message_to_sign(message: Vec<u8>, mut domain_separator: Vec<u8>) -> Vec<u8> {
    domain_separator.extend(message);
    domain_separator
}

fn to_message_point(msg: &[u8], domain_separator: &[u8]) -> blst_p2 {
    let mut msg_prime = domain_separator.to_vec();
    msg_prime.extend(msg);
    let hashed = keccak256(msg_prime);
    let yy = U256::from_be_slice(hashed.as_ref());
    let y = blst_fp2 { fp: [blst_fp::default(), blst_kit::u832_to_fp(yy.to_be_bytes())] };
    let point = blst_kit::blst_fp2_map_to_blst_p2(y);
    point
}

fn to_message_point_hash(msg: &[u8], domain_separator: &[u8]) -> blst_fp2 {
    let mut msg_prime = domain_separator.to_vec();
    msg_prime.extend(msg);
    let hashed = keccak256(msg_prime);
    let yy = U256::from_be_slice(hashed.as_ref());
    let y = blst_fp2 { fp: [blst_fp::default(), blst_kit::u832_to_fp(yy.to_be_bytes())] };
    y
}

fn blst_p2_to_G2point(value: blst_p2) -> G2Point {
    let mut out = [0u8; 192];
    unsafe {
        let mut affine = blst_p2_affine::default();
        blst_p2_to_affine(&mut affine, &value);
        blst_p2_affine_serialize(out.as_mut_ptr(), &affine);
    }
    sol_kit::bytes_to_G2Point(&out)
}

fn blst_p2_affine_to_G2point(value: blst_p2_affine) -> G2Point {
    let mut out = [0u8; 192];
    unsafe {
        blst_p2_affine_serialize(out.as_mut_ptr(), &value);
    }
    sol_kit::bytes_to_G2Point(&out)
}

fn sign(sk: SecretKey, msg: &[u8], domain_separator: &[u8]) -> G2Point {
    let scalar = sk.to_bytes();
    let msg_point = to_message_point(msg, domain_separator);

    let mut signature = blst_p2::default();
    unsafe {
        blst_p2_mult(&mut signature, &msg_point, scalar.as_ptr(), 256);
    }
    let mut signature_affine = blst_p2_affine::default();
    unsafe {
        blst_p2_to_affine(&mut signature_affine, &signature);
    }
    blst_p2_affine_to_G2point(signature_affine)
}

#[tokio::test]
async fn tt() -> eyre::Result<()> {
    let a: Vec<u8> = vec![1; 32];
    let sk = SecretKey::key_gen(&a)?;
    let sk_bytes = sk.clone().to_bytes();
    let sk_u256 = U256::from_be_bytes(sk_bytes);
    let pk = sk.public_key();
    let g1 = sol_kit::pubkey_to_G1Point(pk.clone());
    println!("g1 {:?}", g1);
    let message = vec![1, 2, 3];
    let domain_separator = vec![2, 3, 4];

    // let g2 = sign(sk, &message, &domain_separator);
    // println!("g2 {:?}", g2);
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let operator_address = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(Url::from_str("http://127.0.0.1:8545")?);

    let address: Address = "0x8ce361602B935680E8DeC218b820ff5056BeB7af".parse().unwrap();
    let bls_contract = BLS::new(address, provider.clone());

    let pk = bls_contract.toPublicKey(sk_u256).call().await?;
    println!("pubkey {:?}", pk._0);
    let gen_g1 = sol_kit::bytes_to_G1Point(blst_kit::compress(blst_kit::to_public_key(sk_bytes)));
    println!("pubkey {gen_g1:?}");
    assert!(gen_g1 == pk._0);
    // let add = bls_contract.G1Add(g1.clone(), g1.clone()).call().await?;
    // println!("Gg {add:?}");
    // let a = bls_contract.nothing().call().await?;
    // let b = bls_contract
    //     .toMessagePointHash(message.clone().into(), domain_separator.clone().into())
    //     .call()
    //     .await?;
    // println!("message point {:?}", b._0.c1.b.to_be_bytes::<32>());
    // let b2 = blst_kit::blst_fp2_ser(to_message_point_hash(&message, &domain_separator));
    // println!("message point {b2:?}");
    // let res = bls_contract.verify(message.into(), g2, g1, domain_separator.into()).call().await?;
    // println!("res : {res:?}");
    Ok(())
}
