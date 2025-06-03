use std::fs;

use alloy_primitives::{hex, Address};
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};

use crate::utils::setup_env;

pub const ELF_POI: &[u8] = include_elf!("taiyi-poi");
pub const _ELF_PONI: &[u8] = include_elf!("taiyi-poni");
pub const ELF_VERIFIER: &[u8] = include_elf!("taiyi-zkvm-verifier");

// TODO: type A not included test,
// TODO: type B not included test,

#[derive(Serialize, Deserialize)]
struct TestDataPreconfRequestTypeA {
    vk: String,
    proof: String,         // Hex encoded proof
    public_values: String, // Hex encoded public values
    preconf_request: PreconfRequestTypeA,
    abi_encoded_preconf_request: String,
    genesis_time: u64,
    taiyi_core: Address,
}

#[derive(Serialize, Deserialize)]
struct TestDataPreconfRequestTypeB {
    vk: String,
    proof: String,         // Hex encoded proof
    public_values: String, // Hex encoded public values
    preconf_request: PreconfRequestTypeB,
    abi_encoded_preconf_request: String,
    genesis_time: u64,
    taiyi_core: Address,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn verify_poi_preconf_type_a_included_proof() -> eyre::Result<()> {
    // Read proof from file
    let proof =
        SP1ProofWithPublicValues::load("test-data/poi-preconf-type-a-included-proof.bin").unwrap();

    // Read json data
    let test_data =
        fs::read_to_string("test-data/poi-preconf-type-a-included-test-data.json").unwrap();
    let test_data: TestDataPreconfRequestTypeA = serde_json::from_str(&test_data).unwrap();

    let (taiyi_handle, _) = setup_env().await?;

    let public_values = hex::decode(test_data.public_values).unwrap();
    let vk = test_data.vk;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof.bytes());
    stdin.write_vec(public_values);
    stdin.write(&vk);

    // Verify proof
    let client = ProverClient::builder().cpu().build();
    let (_, report) = client.execute(ELF_VERIFIER, &stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);

    drop(taiyi_handle);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn verify_poi_preconf_type_a_multiple_txs_included_proof() -> eyre::Result<()> {
    // Read proof from file
    let proof = SP1ProofWithPublicValues::load(
        "test-data/poi-preconf-type-a-multiple-txs-included-proof.bin",
    )
    .unwrap();

    // Read json data
    let test_data =
        fs::read_to_string("test-data/poi-preconf-type-a-multiple-txs-included-test-data.json")
            .unwrap();
    let test_data: TestDataPreconfRequestTypeA = serde_json::from_str(&test_data).unwrap();

    let (taiyi_handle, _) = setup_env().await?;

    let public_values = hex::decode(test_data.public_values).unwrap();
    let vk = test_data.vk;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof.bytes());
    stdin.write_vec(public_values);
    stdin.write(&vk);

    // Verify proof
    let client = ProverClient::builder().cpu().build();
    let (_, report) = client.execute(ELF_VERIFIER, &stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);

    drop(taiyi_handle);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore]
async fn verify_poi_preconf_type_b_included_proof() -> eyre::Result<()> {
    // Read proof from file
    let proof =
        SP1ProofWithPublicValues::load("test-data/poi-preconf-type-b-included-proof.bin").unwrap();

    // Read json data
    let test_data =
        fs::read_to_string("test-data/poi-preconf-type-b-included-test-data.json").unwrap();
    let test_data: TestDataPreconfRequestTypeB = serde_json::from_str(&test_data).unwrap();

    println!("preconf b digest: {:?}", test_data.preconf_request.digest(3_151_908));

    let (taiyi_handle, _) = setup_env().await?;

    let public_values = hex::decode(test_data.public_values).unwrap();
    let vk = test_data.vk;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof.bytes());
    stdin.write_vec(public_values);
    stdin.write(&vk);

    // Verify proof
    let client = ProverClient::builder().cpu().build();
    let (_, report) = client.execute(ELF_VERIFIER, &stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);

    drop(taiyi_handle);
    Ok(())
}
