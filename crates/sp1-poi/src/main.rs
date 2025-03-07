#![allow(clippy::unwrap_used)]
#![no_main]

use core::panic;
use std::collections::HashSet;

use alloy_consensus::{Header, Transaction};
use alloy_eips::eip4844::DATA_GAS_PER_BLOB;
use alloy_primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use hex::ToHex;
use taiyi_zkvm_types::{types::*, utils::*};

sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolType};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint64 proofBlockNumber;
        bytes32 proofBlockHash;
        address gatewayAddress;
        bytes signature;
    }
}

pub fn main() {
    // Read an input to the program.
    let preconf = sp1_zkvm::io::read::<String>(); // preconfirmation request encoded as serde string (TODO: change to bytes?)
    let is_type_a = sp1_zkvm::io::read::<bool>(); // true if the preconf req is of type A, false otherwise
    let inclusion_block_header = sp1_zkvm::io::read::<Header>(); // block header of the inclusion block
    let inclusion_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the inclusion block
    let previous_block_header = sp1_zkvm::io::read::<Header>(); // block header of the previous block
    let previous_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the previous block
    let gateway_address = sp1_zkvm::io::read::<Address>(); // address of the gateway

    assert_eq!(inclusion_block_header.hash_slow(), inclusion_block_hash);
    assert_eq!(previous_block_header.hash_slow(), previous_block_hash);
    assert_eq!(inclusion_block_header.parent_hash, previous_block_hash);

    // Commit to the public data (public values).
    let preconf_sig: String;
    // sp1_zkvm::io::commit(&inclusion_block_header.number);
    // sp1_zkvm::io::commit(&inclusion_block_hash);

    if is_type_a {
        let preconf_req_a = serde_json::from_str::<PreconfTypeA>(&preconf).unwrap();
        let txs = preconf_req_a.preconf.clone().transactions;

        assert!(
            gateway_address
                == preconf_req_a
                    .preconf
                    .preconf_sig
                    .recover_address_from_msg(preconf_req_a.preconf.digest())
                    .unwrap()
        ); // check that the gateway address matches the preconf req type a signer

        // sp1_zkvm::io::commit(&gateway_address);
        // sp1_zkvm::io::commit(&preconf_req_a.preconf.preconf_sig.as_bytes().encode_hex::<String>()); // unique commitment to the preconf req type a
        preconf_sig = preconf_req_a.preconf.preconf_sig.as_bytes().encode_hex::<String>();

        // Target slot verification

        assert_eq!(inclusion_block_header.number, preconf_req_a.preconf.target_slot);

        // Account verification

        for (index, tx) in txs.iter().enumerate() {
            let account_merkle_proof = preconf_req_a.account_merkle_proof[index].clone();
            let account_key = account_merkle_proof.address;
            assert_eq!(account_key, tx.recover_signer().unwrap()); // check that the account in proof matches the signer of the transaction
            let account = TrieAccount {
                nonce: account_merkle_proof.nonce,
                balance: account_merkle_proof.balance,
                storage_root: account_merkle_proof.storage_hash,
                code_hash: account_merkle_proof.code_hash,
            };
            verify_proof(
                previous_block_header.state_root,
                Nibbles::unpack(keccak256(account_key)),
                Some(alloy_rlp::encode(account)),
                &account_merkle_proof.account_proof,
            )
            .unwrap(); // verify the account state
            if account.nonce >= tx.nonce() {
                return;
            }
            if tx.is_eip4844() {
                let tx_eip4844 = tx.as_eip4844().unwrap();
                // check balance
                if account.balance
                    < U256::from(
                        inclusion_block_header.blob_fee().unwrap()
                            * DATA_GAS_PER_BLOB as u128
                            * tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len()
                                as u128,
                    )
                {
                    return;
                }
            } else {
                // check balance
                if account.balance
                    < U256::from(inclusion_block_header.base_fee_per_gas.unwrap() * tx.gas_limit())
                {
                    return;
                }
            }
        }

        // Constraints for merkle proofs verification
        assert!(preconf_req_a.tx_merkle_proof.constraints.transactions.len() == txs.len() + 1); // +1 for the anchor tx
        assert!(
            preconf_req_a.tx_merkle_proof.constraints.transactions[0].tx_hash()
                == preconf_req_a.anchor_tx.tx_hash()
        ); // check that the first transaction is the anchor tx
        for (index, tx) in txs.iter().enumerate() {
            assert!(
                preconf_req_a.tx_merkle_proof.constraints.transactions[index + 1].tx_hash()
                    == tx.tx_hash()
            ); // check that the transactions are in the correct order
        }
        assert!(preconf_req_a.tx_merkle_proof.proofs.generalized_indexes.is_sorted());
        // check that the generalized indexes are sorted

        // Anchor/sponsorship tx verification (correct smart contract call and data passed)

        let anchor_tx = preconf_req_a.anchor_tx;
        assert!(anchor_tx.to().unwrap() == address!("894B19A54A829b00Ad9F1394DD82cB6746531ce0")); // taiyi core address
        let sponsor_call = sponsorEthBatchCall::abi_decode(anchor_tx.input(), true).unwrap();
        let mut senders_found: HashSet<Address> = HashSet::new();
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            for tx in txs.iter() {
                if recipient == &tx.recover_signer().unwrap() {
                    // TODO: check amount
                    senders_found.insert(tx.recover_signer().unwrap());
                    break;
                }
            }
        }
        if senders_found.len()
            != txs.iter().map(|tx| tx.recover_signer().unwrap()).collect::<HashSet<Address>>().len()
        {
            panic!("no sponsorship tx for some senders.");
        }

        // User transactions and anchor tx inclusion

        assert_eq!(preconf_req_a.tx_merkle_proof.root, inclusion_block_header.transactions_root);
        verify_multiproofs(
            &preconf_req_a.tx_merkle_proof.constraints,
            &preconf_req_a.tx_merkle_proof.proofs,
            preconf_req_a.tx_merkle_proof.root,
        )
        .unwrap();
    } else {
        let preconf_req_b = serde_json::from_str::<PreconfTypeB>(&preconf).unwrap();
        let tx = preconf_req_b.preconf.clone().transaction;

        assert!(
            gateway_address
                == preconf_req_b
                    .preconf
                    .preconf_sig
                    .recover_address_from_msg(preconf_req_b.preconf.digest())
                    .unwrap()
        ); // check that the gateway address matches the preconf req type a signer

        // sp1_zkvm::io::commit(&gateway_address);
        // sp1_zkvm::io::commit(&preconf_req_b.preconf.preconf_sig.as_bytes().encode_hex::<String>()); // unique commitment to the preconf req type b
        preconf_sig = preconf_req_b.preconf.preconf_sig.as_bytes().encode_hex::<String>();

        // Target slot verification

        assert_eq!(inclusion_block_header.number, preconf_req_b.preconf.allocation.target_slot);

        // Account verification

        let account_merkle_proof = preconf_req_b.account_merkle_proof.clone();
        let account_key = account_merkle_proof.address;
        assert_eq!(account_key, tx.recover_signer().unwrap()); // check that the account in proof matches the signer of the transaction
        let account = TrieAccount {
            nonce: account_merkle_proof.nonce,
            balance: account_merkle_proof.balance,
            storage_root: account_merkle_proof.storage_hash,
            code_hash: account_merkle_proof.code_hash,
        };
        verify_proof(
            previous_block_header.state_root,
            Nibbles::unpack(keccak256(account_key)),
            Some(alloy_rlp::encode(account)),
            &account_merkle_proof.account_proof,
        )
        .unwrap(); // verify the account state
        if account.nonce >= tx.nonce() {
            return;
        }
        if tx.is_eip4844() {
            let tx_eip4844 = tx.as_eip4844().unwrap();
            // check balance
            if account.balance
                < U256::from(
                    inclusion_block_header.blob_fee().unwrap()
                        * DATA_GAS_PER_BLOB as u128
                        * tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len() as u128,
                )
            {
                return;
            }
        } else {
            // check balance
            if account.balance
                < U256::from(inclusion_block_header.base_fee_per_gas.unwrap() * tx.gas_limit())
            {
                return;
            }
        }

        // Constraints for merkle proofs verification
        assert!(preconf_req_b.tx_merkle_proof.constraints.transactions.len() == 2); // only verify the user tx and the sponsorship tx
        assert!(
            preconf_req_b.tx_merkle_proof.constraints.transactions[0].tx_hash() == tx.tx_hash()
        ); // check that the user tx is the first transaction
        assert!(
            preconf_req_b.tx_merkle_proof.constraints.transactions[1].tx_hash()
                == preconf_req_b.sponsorship_tx.tx_hash()
        ); // check that the sponsorship tx is the second transaction
        assert!(
            preconf_req_b.tx_merkle_proof.proofs.generalized_indexes[0]
                < preconf_req_b.tx_merkle_proof.proofs.generalized_indexes[1]
        ); // check that the user tx is before the sponsorship tx

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

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        proofBlockNumber: inclusion_block_header.number,
        proofBlockHash: inclusion_block_hash,
        gatewayAddress: gateway_address,
        signature: Bytes::from(preconf_sig),
    });

    // Commit the public values of the program.
    sp1_zkvm::io::commit_slice(&bytes);
}
