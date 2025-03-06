use std::collections::HashMap;

use alloy_primitives::{TxHash, B256};
use alloy_sol_types::sol;

use crate::types::{ConstraintsData, InclusionProofs, ProofError};

fn total_leaves(constraints: &ConstraintsData) -> usize {
    constraints.proof_data.len()
}

pub fn verify_multiproofs(
    constraints: &ConstraintsData,
    proofs: &InclusionProofs,
    root: B256,
) -> Result<(), ProofError> {
    // Check if the length of the leaves and indices match
    if proofs.transaction_hashes.len() != proofs.generalized_indexes.len() {
        return Err(ProofError::LengthMismatch);
    }

    let total_leaves = total_leaves(constraints);

    // Check if the total leaves matches the proofs provided
    if total_leaves != proofs.total_leaves() {
        return Err(ProofError::LeavesMismatch);
    }

    // Get all the leaves from the saved constraints
    let mut leaves = Vec::with_capacity(proofs.total_leaves());
    let proof_data_map: HashMap<TxHash, B256> = constraints.proof_data.iter().cloned().collect();

    // NOTE: Get the leaves from the constraints cache by matching the saved hashes. We need the
    // leaves in order to verify the multiproof.
    for hash in &proofs.transaction_hashes {
        if let Some(leaf) = proof_data_map.get(hash) {
            leaves.push(B256::from(leaf.0));
        } else {
            return Err(ProofError::MissingHash(*hash));
        }
    }

    // Verify the Merkle multiproof against the root
    ssz_rs::multiproofs::verify_merkle_multiproof(
        &leaves,
        &proofs.merkle_hashes,
        &proofs.generalized_indexes,
        root,
    )
    .map_err(|_| ProofError::VerificationFailed)?;

    Ok(())
}

sol! {
    function sponsorEthBatch(address[] calldata recipients, uint256[] calldata amounts);
}
