#![allow(clippy::unwrap_used)]
#![no_main]

use core::panic;

use alloy_consensus::{Header, Transaction};
use alloy_eips::eip4844::DATA_GAS_PER_BLOB;
use alloy_primitives::address;
use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolCall;
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use hex::ToHex;
use taiyi_zkvm_types::types::*;
use taiyi_zkvm_types::utils::*;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    let preconf = sp1_zkvm::io::read::<String>(); // preconfirmation request encoded as serde string (TODO: change to bytes?)
    let is_type_a = sp1_zkvm::io::read::<bool>(); // true if the preconf req is of type A, false otherwise
    let inclusion_block_header = sp1_zkvm::io::read::<Header>(); // block header of the inclusion block
    let inclusion_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the inclusion block
    let previous_block_header = sp1_zkvm::io::read::<Header>(); // block header of the previous block
    let previous_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the previous block

    assert_eq!(inclusion_block_header.hash_slow(), inclusion_block_hash);
    assert_eq!(previous_block_header.hash_slow(), previous_block_hash);
    assert_eq!(inclusion_block_header.parent_hash, previous_block_hash);

    // Commit to the public data (public values).
    sp1_zkvm::io::commit(&inclusion_block_header.number);
    sp1_zkvm::io::commit(&inclusion_block_hash);

    if is_type_a {
        // TODO: not yet implemented in Taiyi
        // TODO: commit to the preconf request type A
    } else {
        let preconf_req_b = serde_json::from_str::<PreconfTypeB>(&preconf).unwrap();
        let tx = preconf_req_b.preconf.clone().transaction;

        sp1_zkvm::io::commit(&preconf_req_b.preconf.preconf_sig.as_bytes().encode_hex::<String>()); // unique commitment to the preconf req type b
        sp1_zkvm::io::commit(
            &preconf_req_b
                .preconf
                .preconf_sig
                .recover_address_from_msg(preconf_req_b.preconf.digest())
                .unwrap(),
        );

        // Constraints for merkle proofs verification
        assert!(preconf_req_b.tx_merkle_proof.constraints.transactions.len() == 2); // only verify the user tx and the sponsorship tx
        assert!(
            preconf_req_b.tx_merkle_proof.constraints.transactions[0].tx_hash() == tx.tx_hash()
        ); // check that the user tx is the first transaction
        assert!(
            preconf_req_b.tx_merkle_proof.constraints.transactions[1].tx_hash()
                == preconf_req_b.sponsorship_tx.tx_hash()
        ); // check that the sponsorship tx is the second transaction

        // Account verification

        let account_key = preconf_req_b.account_merkle_proof.address;
        assert_eq!(account_key, tx.recover_signer().unwrap()); // check that the account in proof matches the signer of the transaction
        let account = TrieAccount {
            nonce: preconf_req_b.account_merkle_proof.nonce,
            balance: preconf_req_b.account_merkle_proof.balance,
            storage_root: preconf_req_b.account_merkle_proof.storage_hash,
            code_hash: preconf_req_b.account_merkle_proof.code_hash,
        };
        verify_proof(
            previous_block_header.state_root,
            Nibbles::unpack(keccak256(account_key)),
            Some(alloy_rlp::encode(account)),
            &preconf_req_b.account_merkle_proof.account_proof,
        )
        .unwrap(); // verify the account state
        assert!(account.nonce < tx.nonce()); // check nonce
        if tx.is_eip4844() {
            let tx_eip4844 = tx.as_eip4844().unwrap();
            assert!(
                account.balance
                    >= U256::from(
                        inclusion_block_header.blob_fee().unwrap()
                            * DATA_GAS_PER_BLOB as u128
                            * tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len()
                                as u128
                    )
            ); // check balance
        } else {
            assert!(
                account.balance
                    >= U256::from(
                        inclusion_block_header.base_fee_per_gas.unwrap() * tx.gas_limit()
                    )
            ); // check balance
        }

        // Target slot verification

        assert_eq!(inclusion_block_header.number, preconf_req_b.preconf.allocation.target_slot);

        // Sponsorship tx verification (correct smart contract call and data passed)
        let sponsorship_tx = preconf_req_b.sponsorship_tx;
        assert!(
            sponsorship_tx.to().unwrap() == address!("894B19A54A829b00Ad9F1394DD82cB6746531ce0")
        ); // taiyi core address
        let sponsor_call = sponsorEthBatchCall::abi_decode(sponsorship_tx.input(), true).unwrap();
        let mut sender_found = false;
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            if recipient == &tx.recover_signer().unwrap() {
                // TODO: check amount
                sender_found = true;
                break;
            }
        }
        if !sender_found {
            panic!("no sponsorship tx for sender.");
        }

        // User transaction and sponsorship tx inclusion

        assert_eq!(preconf_req_b.tx_merkle_proof.root, inclusion_block_header.transactions_root);
        verify_multiproofs(
            &preconf_req_b.tx_merkle_proof.constraints,
            &preconf_req_b.tx_merkle_proof.proofs,
            preconf_req_b.tx_merkle_proof.root,
        )
        .unwrap();
    }
}
