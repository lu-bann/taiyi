//! A program that verifies a Plonk proof in SP1.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::PlonkVerifier;

pub fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = sp1_zkvm::io::read_vec();
    let sp1_public_values = sp1_zkvm::io::read_vec();
    let sp1_vkey_hash: String = sp1_zkvm::io::read();

    // Verify the plonk proof.
    let plonk_vk = *sp1_verifier::PLONK_VK_BYTES;

    println!("cycle-tracker-start: verify");
    let result = PlonkVerifier::verify(&proof, &sp1_public_values, &sp1_vkey_hash, plonk_vk);
    println!("cycle-tracker-end: verify");

    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {e}");
        }
    }
}
