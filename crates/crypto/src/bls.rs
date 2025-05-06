use std::str::FromStr;

use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_provider::network::EthereumWallet;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolValue};
use blst::min_pk::{
    PublicKey as BlsPubleKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use ethereum_consensus::crypto::{PublicKey, SecretKey, Signature};
use reqwest::Url;

use crate::precompile::{
    g1_msm, g2_msm as g2_mul_precompile, map_fp2_to_g2 as map_fp2_to_g2_precompile,
};
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
    }
}

pub fn sign(sk: U256, msg: &[u8], domain_separator: &[u8]) -> G2Point {
    let fp2 = to_message_point(msg, domain_separator);
    let g2 = map_fp2_to_g2(fp2);
    let g2_mul = g2_mul(g2, sk);
    g2_mul
}

pub fn to_message_point(msg: &[u8], domain_separator: &[u8]) -> Fp2 {
    let mut msg_prime = domain_separator.to_vec();
    msg_prime.extend(msg);
    let hashed = keccak256(msg_prime);
    let yy = U256::from_be_slice(hashed.as_ref());
    Fp2 { c0: Fp { a: U256::from(0), b: U256::from(0) }, c1: Fp { a: U256::from(0), b: yy } }
}

pub fn map_fp2_to_g2(fp2: Fp2) -> G2Point {
    let input = fp2.abi_encode_sequence();
    let input_bytes = Bytes::from(input);
    let output = map_fp2_to_g2_precompile(&input_bytes).unwrap();
    let output_bytes = output.as_ref();
    let output_g2 = G2Point::abi_decode_sequence(output_bytes, false).unwrap();
    output_g2
}

pub fn g2_mul(point: G2Point, scalar: U256) -> G2Point {
    let input = (point, scalar).abi_encode_sequence();
    let input_bytes = Bytes::from(input);
    let output = g2_mul_precompile(&input_bytes).unwrap();
    let output_bytes = output.as_ref();
    let output_g2 = G2Point::abi_decode_sequence(output_bytes, false).unwrap();
    output_g2
}

pub fn to_public_key(sk: U256) -> G1Point {
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
    let output = g1_msm(&input_bytes).unwrap();
    let output_bytes = output.as_ref();
    let output_g1 = G1Point::abi_decode_sequence(output_bytes, false).unwrap();
    output_g1
}

#[tokio::test]
async fn tt() -> eyre::Result<()> {
    let sk = U256::from(1032123143561346134614u128);
    let pk = to_public_key(sk);
    let message = vec![1, 2, 3];
    let domain_separator = vec![2, 3, 4];

    let g2 = sign(sk, &message, &domain_separator);
    println!("g2 {:?}", g2);
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let operator_address = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(signer.clone()))
        .on_http(Url::from_str("http://127.0.0.1:8545")?);

    let address: Address = "0x8ce361602B935680E8DeC218b820ff5056BeB7af".parse().unwrap();
    let bls_contract = BLS::new(address, provider.clone());

    let res = bls_contract.verify(message.into(), g2, pk, domain_separator.into()).call().await?;
    println!("res : {res:?}");
    Ok(())
}
