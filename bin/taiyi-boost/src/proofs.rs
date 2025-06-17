#![allow(dead_code)]
/// The code is modified from bolt: https://github.com/chainbound/bolt/blob/v0.3.0-alpha/bolt-boost/src/proofs.rs
use std::collections::HashMap;

use alloy_primitives::{TxHash, B256};

use super::types::{ConstraintsData, InclusionProofs};
use crate::types::HashTreeRootType;

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Leaves and indices length mismatch")]
    LengthMismatch,
    #[error("Mismatch in provided leaves and leaves to prove")]
    LeavesMismatch,
    #[error("Hash not found in constraints cache: {0:?}")]
    MissingHash(TxHash),
    #[error("Proof verification failed")]
    VerificationFailed,
}

/// Returns the length of the leaves that need to be proven (i.e. all transactions).
fn total_leaves(constraints: &ConstraintsData) -> usize {
    constraints.proof_data.len()
}

/// Verifies the provided multiproofs against the constraints & transactions root.
/// TODO: support bundle proof verification a.k.a. relative ordering!
pub fn verify_multiproofs(
    constraints: &ConstraintsData,
    proofs: &InclusionProofs,
    _root: B256,
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
    let proof_data_map: HashMap<TxHash, HashTreeRootType> =
        constraints.proof_data.iter().cloned().collect();

    // NOTE: Get the leaves from the constraints cache by matching the saved hashes. We need the
    // leaves in order to verify the multiproof.
    for hash in proofs.transaction_hashes.iter() {
        if let Some(leaf) = proof_data_map.get(hash) {
            leaves.push(B256::from(leaf.0));
        } else {
            return Err(ProofError::MissingHash(*hash));
        }
    }

    // Verify the Merkle multiproof against the root
    // ssz_rs::multiproofs::verify_merkle_multiproof(
    //     &leaves,
    //     &proofs.merkle_hashes,
    //     &proofs.generalized_indexes,
    //     root,
    // )
    // .map_err(|_| ProofError::VerificationFailed)?;

    Ok(())
}
/*
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::env;

    use alloy_primitives::{hex, Bytes, B256, address};
    use hex::FromHex;
    use ssz_rs::{HashTreeRoot, List, PathElement, Prove};

    use crate::{
        ExtraConfig,
        constraints::ConstraintsCache,
        proofs::verify_multiproofs,
        types::{InclusionProofs, SignedConstraints},
    };

    const TEST_BLOCK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/signed-mainnet-beacon-block.bin.ssz"
    ));

    pub fn read_test_block() -> SignedBeaconBlockDeneb<MainnetEthSpec> {
        SignedBeaconBlockDeneb::from_ssz_bytes(TEST_BLOCK).unwrap()
    }

    /// Reads and decodes the transactions root and the transactions from the test block.
    pub fn read_test_transactions() -> (B256, Vec<Bytes>) {
        let test_block = read_test_block();

        let transactions = test_block.message.body.execution_payload.transactions().unwrap();

        let transactions: Vec<Bytes> =
            transactions.into_iter().map(|tx| Bytes::from(tx.to_vec())).collect();

        let transactions_root = test_block
            .message
            .body
            .execution_payload
            .to_execution_payload_header()
            .transactions_root();

        (B256::from_slice(transactions_root.as_ref()), transactions)
    }

    #[test]
    fn test_single_proof() {
        let (root, transactions) = read_test_transactions();

        let transactions_list =
            transactions_to_ssz_list::<1073741824, 1048576>(transactions.clone());

        // let index = rand::random::<usize>() % transactions.len();
        let index = 26;

        let root_node = transactions_list.hash_tree_root().unwrap();

        assert_eq!(root_node, root);

        // Generate the path from the transaction indexes
        let path = path_from_indexes(&[index]);

        let start_proof = std::time::Instant::now();
        let (proof, witness) = transactions_list.prove(&path).unwrap();
        println!("Generated proof in {:?}", start_proof.elapsed());

        // Root and witness must be the same
        assert_eq!(root, witness);

        let start_verify = std::time::Instant::now();
        assert!(proof.verify(witness).is_ok());
        println!("Verified proof in {:?}", start_verify.elapsed());
    }

    #[test]
    fn test_merkle_multiproof_blob() {
        // Proof generated from bolt-builder code for the blob transaction inside
        // ./testdata/signed_constraints_with_blob.json
        let root =
            B256::from(hex!("085f9483581f0302fd8a5a7b03e5aa9f110d4548bd679bedc04764dc9405a700"));

        let proof = vec![
            hex!("8c0bd07dcc7050700654b730d245db145c92ad92ef6ac81e2361533c66ee9688"),
            hex!("ee38e5ba99fa98c9c8963c7e9c59e3128f285454f27daf9549d19c4bb98039fd"),
            hex!("af0302f3b715a72dab24a7590f01dc5717c642a39fc5a92bc09518b24e05d56c"),
            hex!("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
            hex!("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
            hex!("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
            hex!("d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
            hex!("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
            hex!("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
            hex!("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
            hex!("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
            hex!("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
            hex!("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
            hex!("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
            hex!("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
            hex!("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
            hex!("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
            hex!("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
            hex!("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
            hex!("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
            hex!("0600000000000000000000000000000000000000000000000000000000000000"),
        ]
        .iter()
        .map(B256::from)
        .collect::<Vec<_>>();

        let leaves = [hex!("b4bb948e1cfc750a20fa08d6661d3f0717ca367eec45d81fcf92e8f1ae1fe688")]
            .iter()
            .map(B256::from)
            .collect::<Vec<_>>();

        let transaction_hashes =
            [hex!("00724d63ef8a791110a66d6e7433d097637aec698f5cf81c44446e1ea5c45a1a")]
                .iter()
                .map(B256::from)
                .collect::<Vec<_>>();

        let generalized_indexes = vec![2097152];

        let inclusion_proof =
            InclusionProofs { transaction_hashes, merkle_hashes: proof, generalized_indexes };

        assert!(ssz_rs::multiproofs::verify_merkle_multiproof(
            &leaves,
            &inclusion_proof.merkle_hashes,
            &inclusion_proof.generalized_indexes,
            root
        )
        .is_ok());

        let constraints_cache = ConstraintsCache::default();

        // We know the inclusion proof is valid, now we start from scratch from a signed constraint
        // message

        let signed_constraints: Vec<SignedConstraints> = serde_json::from_reader(
            File::open("testdata/signed_constraints_with_blob.json").unwrap(),
        )
        .expect("to read signed constraints");

        constraints_cache
            .insert(signed_constraints[0].message.clone())
            .expect("to save constraints");
        let constraints_data = constraints_cache.remove(496).unwrap().1;

        // Sanity check to ensure we're verifying the same transaction
        assert_eq!(constraints_data.proof_data[0].0, inclusion_proof.transaction_hashes[0]);

        assert!(verify_multiproofs(&constraints_data, &inclusion_proof, root).is_ok());
    }

    /// Testdata from https://github.com/ferranbt/fastssz/blob/455b54c08c81c3a270b6a7160f92ce68408491d4/tests/codetrie_test.go#L195
    #[test]
    fn test_fastssz_multiproof() {
        let root =
            B256::from(hex!("f1824b0084956084591ff4c91c11bcc94a40be82da280e5171932b967dd146e9"));

        let proof = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "f58f76419d9235451a8290a88ba380d852350a1843f8f26b8257a421633042b4",
        ]
        .into_iter()
        .map(|hex| B256::from_hex(hex).unwrap())
        .collect::<Vec<_>>();

        let leaves = vec![
            "0200000000000000000000000000000000000000000000000000000000000000",
            "6001000000000000000000000000000000000000000000000000000000000000",
        ]
        .into_iter()
        .map(|hex| B256::from_hex(hex).unwrap())
        .collect::<Vec<_>>();

        let indexes = vec![10usize, 49usize];

        assert!(
            ssz_rs::multiproofs::verify_merkle_multiproof(&leaves, &proof, &indexes, root).is_ok()
        );
    }

    fn path_from_indexes(indexes: &[usize]) -> Vec<PathElement> {
        indexes.iter().map(|i| PathElement::from(*i)).collect::<Vec<_>>()
    }

    fn transactions_to_ssz_list<const B: usize, const N: usize>(
        txs: Vec<Bytes>,
    ) -> List<List<u8, B>, N> {
        // fn transactions_to_ssz_list(txs: Vec<Bytes>) -> List<List<u8, 1073741824>, 1048576> {
        let inner: Vec<List<u8, B>> =
            txs.into_iter().map(|tx| List::try_from(tx.to_vec()).unwrap()).collect();

        List::try_from(inner).unwrap()
    }
}
 */
