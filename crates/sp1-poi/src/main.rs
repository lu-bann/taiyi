#![allow(clippy::unwrap_used)]
#![no_main]

use core::panic;
use std::{collections::HashSet, str::FromStr, sync::Arc};

use alloy_consensus::{Header, Transaction, TxEnvelope};
use alloy_eips::{eip2718::Decodable2718, eip4844::DATA_GAS_PER_BLOB};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use eth_trie::{EthTrie, MemoryDB, Trie};
use taiyi_zkvm_types::{types::*, utils::*};

sp1_zkvm::entrypoint!(main);

const SLOT_TIME: u64 = 12;

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_TIME
}

pub fn main() {
    // Read an input to the program.
    let preconf = sp1_zkvm::io::read::<String>(); // preconfirmation request encoded as serde string (TODO: change to bytes?)
    let is_type_a = sp1_zkvm::io::read::<bool>(); // true if the preconf req is of type A, false otherwise
    let inclusion_block_header = sp1_zkvm::io::read::<String>(); // block header of the inclusion block encoded as serde string
    let inclusion_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the inclusion block
    let previous_block_header = sp1_zkvm::io::read::<String>(); // block header of the previous block encoded as serde string
    let previous_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the previous block
    let gateway_address = sp1_zkvm::io::read::<Address>(); // address of the gateway
    let genesis_timestamp = sp1_zkvm::io::read::<u64>(); // genesis timestamp

    let inclusion_block_header = serde_json::from_str::<Header>(&inclusion_block_header).unwrap();
    let previous_block_header = serde_json::from_str::<Header>(&previous_block_header).unwrap();

    assert_eq!(inclusion_block_header.hash_slow(), inclusion_block_hash);
    assert_eq!(previous_block_header.hash_slow(), previous_block_hash);
    assert_eq!(inclusion_block_header.parent_hash, previous_block_hash);

    let preconf_sig: Vec<u8>;
    if is_type_a {
        let preconf_req_a = serde_json::from_str::<PreconfTypeA>(&preconf).unwrap();
        let txs = preconf_req_a.preconf.clone().transactions;

        let chain_id = txs.first().unwrap().chain_id().unwrap();

        assert!(
            gateway_address
                == preconf_req_a
                    .preconf
                    .preconf_sig
                    .recover_address_from_prehash(&preconf_req_a.preconf.digest(chain_id))
                    .unwrap()
        ); // check that the gateway address matches the preconf req type a signer

        preconf_sig = preconf_req_a.preconf.preconf_sig.as_bytes().to_vec();

        // Encode the public values of the program.
        let bytes = (
            inclusion_block_header.timestamp,
            inclusion_block_hash,
            gateway_address,
            preconf_sig.clone(),
        )
            .abi_encode_sequence();

        // Target slot verification
        assert_eq!(
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp),
            preconf_req_a.preconf.target_slot
        );

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

            if account.nonce > tx.nonce() {
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
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
                    // Commit the public values of the program.
                    sp1_zkvm::io::commit_slice(&bytes);
                    return;
                }
            } else {
                // check balance
                if account.balance
                    < U256::from(inclusion_block_header.base_fee_per_gas.unwrap() * tx.gas_limit())
                {
                    // Commit the public values of the program.
                    sp1_zkvm::io::commit_slice(&bytes);
                    return;
                }
            }
        }

        // User transactions and anchor tx inclusion
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        assert!(preconf_req_a.tx_merkle_proof.len() == txs.len() + 1); // +1 for the anchor tx
        for (index, merkle_proof) in preconf_req_a.tx_merkle_proof.iter().enumerate() {
            assert!(merkle_proof.root == inclusion_block_header.transactions_root);

            let node = trie
                .verify_proof(
                    merkle_proof.root,
                    merkle_proof.key.as_slice(),
                    merkle_proof.proof.clone(),
                )
                .unwrap()
                .unwrap();

            let tx = TxEnvelope::decode_2718(&mut node.as_slice()).unwrap();

            if index == 0 {
                // check that the first transaction is the anchor tx
                assert!(tx.tx_hash() == preconf_req_a.anchor_tx.tx_hash());
            } else {
                // check that the transactions are in the correct order
                assert!(tx.tx_hash() == txs[index - 1].tx_hash());
            }
        }

        // Anchor/sponsorship tx verification (correct smart contract call and data passed)
        let anchor_tx = preconf_req_a.anchor_tx;
        // TODO: How to handle different contract addresses for different environments/chains (e2e-tests, testnet, mainnet)?
        assert!(
            anchor_tx.to().unwrap()
                == Address::from_str("0x1127a1e8248ae0ee1d5f1c7094ffd7dc37cbe714").unwrap()
        ); // taiyi core address
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
    } else {
        let preconf_req_b = serde_json::from_str::<PreconfTypeB>(&preconf).unwrap();
        let tx = preconf_req_b.preconf.clone().transaction.unwrap();
        let chain_id = tx.chain_id().unwrap();

        assert!(
            gateway_address
                == preconf_req_b
                    .preconf
                    .preconf_sig
                    .recover_address_from_prehash(&preconf_req_b.preconf.digest(chain_id))
                    .unwrap()
        ); // check that the gateway address matches the preconf req type a signer

        preconf_sig = preconf_req_b.preconf.preconf_sig.as_bytes().to_vec();

        // Encode the public values of the program.
        let bytes = (
            inclusion_block_header.timestamp,
            inclusion_block_hash,
            gateway_address,
            preconf_sig.clone(),
        )
            .abi_encode_sequence();

        // Target slot verification
        assert_eq!(
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp),
            preconf_req_b.preconf.allocation.target_slot
        );

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

        if account.nonce > tx.nonce() {
            // Commit the public values of the program.
            sp1_zkvm::io::commit_slice(&bytes);
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
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return;
            }
        } else {
            // check balance
            if account.balance
                < U256::from(inclusion_block_header.base_fee_per_gas.unwrap() * tx.gas_limit())
            {
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return;
            }
        }

        // User transaction and sponsorship tx inclusion

        // only verify the user tx and the sponsorship tx
        assert!(preconf_req_b.tx_merkle_proof.len() == 2);

        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        for (index, merkle_proof) in preconf_req_b.tx_merkle_proof.iter().enumerate() {
            assert!(merkle_proof.root == inclusion_block_header.transactions_root);

            let node = trie
                .verify_proof(
                    merkle_proof.root,
                    merkle_proof.key.as_slice(),
                    merkle_proof.proof.clone(),
                )
                .unwrap()
                .unwrap();

            let decoded_tx = TxEnvelope::decode_2718(&mut node.as_slice()).unwrap();
            if index == 0 {
                // check that the user tx is the first transaction
                assert!(decoded_tx.tx_hash() == tx.tx_hash());
            } else {
                // check that the sponsorship tx is the second transaction
                assert!(decoded_tx.tx_hash() == preconf_req_b.sponsorship_tx.tx_hash());
            }
        }
        // Sponsorship tx verification (correct smart contract call and data passed)
        let sponsorship_tx = preconf_req_b.sponsorship_tx;

        // TODO: Check if correct
        // TODO: How to handle different contract addresses for different environments/chains (e2e-tests, testnet, mainnet)?
        assert!(
            sponsorship_tx.to().unwrap()
                == Address::from_str("0x1127a1e8248ae0ee1d5f1c7094ffd7dc37cbe714").unwrap()
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
    }

    // Encode the public values of the program.
    let bytes =
        (inclusion_block_header.timestamp, inclusion_block_hash, gateway_address, preconf_sig)
            .abi_encode_sequence();

    // Commit the public values of the program.
    sp1_zkvm::io::commit_slice(&bytes);
}
