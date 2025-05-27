#![no_main]

use core::panic;
use std::{collections::HashSet, str::FromStr, sync::Arc};

use alloy_consensus::{Header, Transaction, TxEnvelope};
use alloy_eips::{
    eip2718::Decodable2718, eip4844::DATA_GAS_PER_BLOB, eip7840::BlobParams,
    merge::SLOT_DURATION_SECS,
};
use alloy_primitives::{keccak256, Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use eth_trie::{EthTrie, MemoryDB, Trie};
use eyre::Ok;
use taiyi_zkvm_types::{types::*, utils::*};

sp1_zkvm::entrypoint!(main);

fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

fn verify() -> eyre::Result<()> {
    println!("DEBUG: Starting poi verification");

    // Read an input to the program.
    let preconf = sp1_zkvm::io::read::<String>(); // preconfirmation request encoded as serde string
    let preconf_signature = sp1_zkvm::io::read::<String>(); // hex-encoded preconfirmation signature
    let is_type_a = sp1_zkvm::io::read::<bool>(); // true if the preconf req is of type A, false otherwise
    let inclusion_block_header = sp1_zkvm::io::read::<String>(); // block header of the inclusion block encoded as serde string
    let inclusion_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the inclusion block
    let previous_block_header = sp1_zkvm::io::read::<String>(); // block header of the previous block encoded as serde string
    let previous_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the previous block
    let underwriter_address = sp1_zkvm::io::read::<Address>(); // address of the underwriter
    let genesis_timestamp = sp1_zkvm::io::read::<u64>(); // genesis timestamp
    let taiyi_core = sp1_zkvm::io::read::<Address>(); // taiyi core address

    println!(
        "DEBUG: Processing {} request for underwriter: {:?}",
        if is_type_a { "Type A" } else { "Type B" },
        underwriter_address
    );
    println!(
        "DEBUG: Inclusion block hash: {:?}, number: {}",
        inclusion_block_hash,
        serde_json::from_str::<Header>(&inclusion_block_header)
            .map(|h| h.number)
            .unwrap_or_default()
    );

    let inclusion_block_header = serde_json::from_str::<Header>(&inclusion_block_header)?;
    let previous_block_header = serde_json::from_str::<Header>(&previous_block_header)?;

    assert_eq!(
        inclusion_block_header.hash_slow(),
        inclusion_block_hash,
        "Inclusion block header hash mismatch: computed {:?} != expected {:?}",
        inclusion_block_header.hash_slow(),
        inclusion_block_hash
    );
    assert_eq!(
        previous_block_header.hash_slow(),
        previous_block_hash,
        "Previous block header hash mismatch: computed {:?} != expected {:?}",
        previous_block_header.hash_slow(),
        previous_block_hash
    );
    assert_eq!(
        inclusion_block_header.parent_hash, previous_block_hash,
        "Block chain continuity broken: inclusion block parent {:?} != previous block hash {:?}",
        inclusion_block_header.parent_hash, previous_block_hash
    );

    let preconf_signature = PrimitiveSignature::from_str(&preconf_signature)?;

    if is_type_a {
        println!("DEBUG: Processing Type A preconf request");
        let preconf_req_a = serde_json::from_str::<PreconfTypeA>(&preconf)?;
        let txs = preconf_req_a.preconf.clone().preconf_tx;
        println!("DEBUG: Type A request contains {} transactions", txs.len());

        let chain_id = match txs.first() {
            Some(tx) => match tx.chain_id() {
                Some(id) => {
                    println!("DEBUG: Chain ID from transaction: {}", id);
                    id
                }
                None => {
                    println!("ERROR: Failed to get chain ID from transaction");
                    panic!("Transaction missing chain ID");
                }
            },
            None => {
                println!("ERROR: No transactions in Type A request");
                panic!("Type A request contains no transactions");
            }
        };

        // Check that the underwriter address matches the preconf req type a signer
        let recovered_address = preconf_signature
            .recover_address_from_prehash(&preconf_req_a.preconf.digest(chain_id))?;

        assert!(
            underwriter_address == recovered_address,
            "Underwriter address mismatch: expected {:?}, got {:?}",
            underwriter_address,
            recovered_address
        );

        // Encode the public values of the program.
        let bytes = (
            inclusion_block_header.timestamp,
            inclusion_block_hash,
            inclusion_block_header.number,
            underwriter_address,
            preconf_signature.as_bytes().to_vec(),
            genesis_timestamp,
            taiyi_core,
        )
            .abi_encode_sequence();

        // Target slot verification
        println!(
            "DEBUG: Verifying target slot: expected {}, actual {}",
            preconf_req_a.preconf.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );
        assert_eq!(
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp),
            preconf_req_a.preconf.target_slot,
            "Target slot mismatch: expected {}, got {}",
            preconf_req_a.preconf.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );

        // Account verification
        println!("DEBUG: Starting account verification for {} transactions", txs.len());
        for (index, tx) in txs.iter().enumerate() {
            println!("DEBUG: Verifying account for transaction {}/{}", index + 1, txs.len());
            let account_merkle_proof = preconf_req_a.account_merkle_proof[index].clone();
            let account_key = account_merkle_proof.address;

            // Check that the account in proof matches the signer of the transaction
            let tx_signer = tx.recover_signer()?;

            assert_eq!(
                account_key, tx_signer,
                "Account key mismatch for tx {}: expected {:?}, got {:?}",
                index, account_key, tx_signer
            );

            let account = TrieAccount {
                nonce: account_merkle_proof.nonce,
                balance: account_merkle_proof.balance,
                storage_root: account_merkle_proof.storage_hash,
                code_hash: account_merkle_proof.code_hash,
            };
            println!(
                "DEBUG: Account state - nonce: {}, balance: {}",
                account.nonce, account.balance
            );

            // Verify the account state
            verify_proof(
                previous_block_header.state_root,
                Nibbles::unpack(keccak256(account_key)),
                Some(alloy_rlp::encode(account)),
                &account_merkle_proof.account_proof,
            )?;

            if account.nonce > tx.nonce() {
                println!(
                    "DEBUG: Account nonce ({}) > tx nonce ({}), verification failed",
                    account.nonce,
                    tx.nonce()
                );
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return Ok(());
            }

            if tx.is_eip4844() {
                println!("DEBUG: Processing EIP4844 transaction");
                let tx_eip4844 =
                    tx.as_eip4844().ok_or(eyre::eyre!("Failed to parse EIP4844 transaction"))?;

                let blob_fee = inclusion_block_header
                    .blob_fee(BlobParams::prague())
                    .ok_or(eyre::eyre!("Failed to get blob fee from inclusion block header"))?;

                let blob_hashes_len =
                    tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len();
                println!("DEBUG: Transaction has {} blob hashes", blob_hashes_len);

                let base_fee = inclusion_block_header
                    .base_fee_per_gas
                    .ok_or(eyre::eyre!("Failed to get base fee from inclusion block header"))?;

                let priority_fee = tx
                    .max_priority_fee_per_gas()
                    .ok_or(eyre::eyre!("Failed to get priority fee from transaction"))?;

                let required_balance = U256::from(
                    blob_fee * DATA_GAS_PER_BLOB as u128 * blob_hashes_len as u128
                        + (base_fee * tx.gas_limit()) as u128
                        + priority_fee * tx.gas_limit() as u128,
                );

                println!(
                    "DEBUG: Required balance: {}, account balance: {}",
                    required_balance, account.balance
                );

                // Check balance
                if account.balance < required_balance {
                    println!(
                        "DEBUG: Insufficient balance for EIP4844 transaction, verification failed"
                    );
                    // Commit the public values of the program.
                    sp1_zkvm::io::commit_slice(&bytes);
                    return Ok(());
                }
            } else {
                println!("DEBUG: Processing standard transaction");

                let base_fee = inclusion_block_header
                    .base_fee_per_gas
                    .ok_or(eyre::eyre!("Failed to load base fee from inclusion block header"))?;

                let priority_fee = tx
                    .max_priority_fee_per_gas()
                    .ok_or(eyre::eyre!("Failed to get priority fee from transaction"))?;

                let required_balance = U256::from(
                    (base_fee * tx.gas_limit()) as u128 + priority_fee * tx.gas_limit() as u128,
                );

                println!(
                    "DEBUG: Required balance: {}, account balance: {}",
                    required_balance, account.balance
                );

                // Check balance
                if account.balance < required_balance {
                    println!("DEBUG: Insufficient balance for transaction, verification failed");
                    // Commit the public values of the program.
                    sp1_zkvm::io::commit_slice(&bytes);
                    return Ok(());
                }
            }
        }

        // User transactions and anchor tx inclusion
        println!("DEBUG: Starting transaction merkle proof verification");
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        assert!(
            preconf_req_a.tx_merkle_proof.len() == txs.len() + 1,
            "Merkle proof count mismatch: expected {} (txs + anchor), got {}",
            txs.len() + 1,
            preconf_req_a.tx_merkle_proof.len()
        ); // +1 for the anchor tx

        println!("DEBUG: Verifying {} merkle proofs", preconf_req_a.tx_merkle_proof.len());
        for (index, merkle_proof) in preconf_req_a.tx_merkle_proof.iter().enumerate() {
            println!(
                "DEBUG: Verifying merkle proof {}/{}",
                index + 1,
                preconf_req_a.tx_merkle_proof.len()
            );
            assert!(
                merkle_proof.root == inclusion_block_header.transactions_root,
                "Merkle proof root mismatch for proof {}: expected {:?}, got {:?}",
                index,
                inclusion_block_header.transactions_root,
                merkle_proof.root
            );

            // Verify the merkle proof
            let node = trie
                .verify_proof(
                    merkle_proof.root,
                    merkle_proof.key.as_slice(),
                    merkle_proof.proof.clone(),
                )?
                .ok_or(eyre::eyre!("Failed to verify merkle proof"))?;

            // Decode the transaction
            let tx = TxEnvelope::decode_2718(&mut node.as_slice())?;

            if index == 0 {
                // check that the first transaction is the anchor tx
                assert!(
                    tx.tx_hash() == preconf_req_a.anchor_tx.tx_hash(),
                    "Anchor transaction hash mismatch: expected {:?}, got {:?}",
                    preconf_req_a.anchor_tx.tx_hash(),
                    tx.tx_hash()
                );
                println!("DEBUG: Verified anchor transaction hash");
            } else {
                // check that the transactions are in the correct order
                assert!(
                    tx.tx_hash() == txs[index - 1].tx_hash(),
                    "Transaction hash mismatch at index {}: expected {:?}, got {:?}",
                    index - 1,
                    txs[index - 1].tx_hash(),
                    tx.tx_hash()
                );
                println!("DEBUG: Verified transaction hash at index {}", index - 1);
            }
        }

        // Anchor/sponsorship tx verification (correct smart contract call and data passed)
        println!("DEBUG: Starting anchor/sponsorship tx verification");
        let anchor_tx = preconf_req_a.anchor_tx;

        // Check that the anchor tx to field matches the taiyi core address
        let anchor_to = anchor_tx.to().ok_or(eyre::eyre!("Anchor tx has no to address"))?;

        assert!(
            anchor_to == taiyi_core,
            "Anchor tx to address mismatch: expected {:?}, got {:?}",
            taiyi_core,
            anchor_to
        );
        println!("DEBUG: Verified anchor tx to address matches taiyi core");

        // Decode the sponsor call
        let sponsor_call = sponsorEthBatchCall::abi_decode(anchor_tx.input(), true)?;

        let mut senders_found: HashSet<Address> = HashSet::new();
        println!("DEBUG: Checking sponsorship for {} transactions", txs.len());
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            for tx in txs.iter() {
                let tx_signer = tx.recover_signer()?;

                if recipient == &tx_signer {
                    // TODO: check amount
                    println!("DEBUG: Found sponsorship for signer: {:?}", tx_signer);
                    senders_found.insert(tx_signer);
                    break;
                }
            }
        }

        let all_signers: HashSet<Address> = txs
            .iter()
            .map(|tx| tx.recover_signer().expect("signer could not be recoverd"))
            .collect();

        println!(
            "DEBUG: Found {} sponsored signers out of {} unique signers",
            senders_found.len(),
            all_signers.len()
        );

        if senders_found.len() != all_signers.len() {
            println!("ERROR: Not all transaction signers are sponsored");
            panic!(
                "Sponsorship verification failed: Found {} sponsored senders but expected {} unique transaction senders. Missing sponsorship for some transactions.",
                senders_found.len(),
                all_signers.len()
            );
        }
        println!("DEBUG: All transaction signers are sponsored");
    } else {
        println!("DEBUG: Processing Type B preconf request");
        let preconf_req_b = serde_json::from_str::<PreconfTypeB>(&preconf)?;

        let tx = preconf_req_b
            .preconf
            .clone()
            .transaction
            .ok_or(eyre::eyre!("Type B preconf request has no transaction"))?;

        let chain_id = tx.chain_id().ok_or(eyre::eyre!("Transaction missing chain ID"))?;

        // Check that the underwriter address matches the preconf req type b signer
        let recovered_address = preconf_signature
            .recover_address_from_prehash(&preconf_req_b.preconf.digest(chain_id))?;

        assert!(
            underwriter_address == recovered_address,
            "Underwriter address mismatch: expected {:?}, got {:?}",
            underwriter_address,
            recovered_address
        );

        // Encode the public values of the program.
        let bytes = (
            inclusion_block_header.timestamp,
            inclusion_block_hash,
            inclusion_block_header.number,
            underwriter_address,
            preconf_signature.as_bytes().to_vec(),
            genesis_timestamp,
            taiyi_core,
        )
            .abi_encode_sequence();

        // Target slot verification
        println!(
            "DEBUG: Verifying target slot: expected {}, actual {}",
            preconf_req_b.preconf.allocation.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );
        assert_eq!(
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp),
            preconf_req_b.preconf.allocation.target_slot,
            "Target slot mismatch: expected {}, got {}",
            preconf_req_b.preconf.allocation.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );

        // Account verification
        println!("DEBUG: Starting account verification for Type B request");
        let account_merkle_proof = preconf_req_b.account_merkle_proof.clone();
        let account_key = account_merkle_proof.address;

        // Check that the account in proof matches the signer of the transaction
        let tx_signer = tx.recover_signer()?;

        assert_eq!(
            account_key, tx_signer,
            "Account key mismatch: expected {:?}, got {:?}",
            account_key, tx_signer
        );

        let account = TrieAccount {
            nonce: account_merkle_proof.nonce,
            balance: account_merkle_proof.balance,
            storage_root: account_merkle_proof.storage_hash,
            code_hash: account_merkle_proof.code_hash,
        };
        println!("DEBUG: Account state - nonce: {}, balance: {}", account.nonce, account.balance);

        // Verify the account state
        verify_proof(
            previous_block_header.state_root,
            Nibbles::unpack(keccak256(account_key)),
            Some(alloy_rlp::encode(account)),
            &account_merkle_proof.account_proof,
        )?;

        if account.nonce > tx.nonce() {
            println!(
                "DEBUG: Account nonce ({}) > tx nonce ({}), verification failed",
                account.nonce,
                tx.nonce()
            );
            // Commit the public values of the program.
            sp1_zkvm::io::commit_slice(&bytes);
            return Ok(());
        }

        if tx.is_eip4844() {
            println!("DEBUG: Processing EIP4844 transaction");
            let tx_eip4844 =
                tx.as_eip4844().ok_or(eyre::eyre!("Failed to parse EIP4844 transaction"))?;

            let blob_fee = inclusion_block_header
                .blob_fee(BlobParams::prague())
                .ok_or(eyre::eyre!("Failed to get blob fee from inclusion block header"))?;

            let blob_hashes_len = tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len();
            println!("DEBUG: Transaction has {} blob hashes", blob_hashes_len);

            let base_fee = inclusion_block_header
                .base_fee_per_gas
                .ok_or(eyre::eyre!("Failed to get base fee from inclusion block header"))?;

            let priority_fee = tx
                .max_priority_fee_per_gas()
                .ok_or(eyre::eyre!("Failed to get priority fee from transaction"))?;

            let required_balance = U256::from(
                blob_fee * DATA_GAS_PER_BLOB as u128 * blob_hashes_len as u128
                    + (base_fee * tx.gas_limit()) as u128
                    + priority_fee * tx.gas_limit() as u128,
            );

            println!(
                "DEBUG: Required balance: {}, account balance: {}",
                required_balance, account.balance
            );

            // Check balance
            if account.balance < required_balance {
                println!(
                    "DEBUG: Insufficient balance for EIP4844 transaction, verification failed"
                );
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return Ok(());
            }
        } else {
            println!("DEBUG: Processing standard transaction");

            let base_fee = inclusion_block_header
                .base_fee_per_gas
                .ok_or(eyre::eyre!("Failed to get base fee from inclusion block header"))?;

            let priority_fee = tx
                .max_priority_fee_per_gas()
                .ok_or(eyre::eyre!("Failed to get priority fee from transaction"))?;

            let required_balance = U256::from(
                (base_fee * tx.gas_limit()) as u128 + priority_fee * tx.gas_limit() as u128,
            );

            println!(
                "DEBUG: Required balance: {}, account balance: {}",
                required_balance, account.balance
            );

            // Check balance
            if account.balance < required_balance {
                println!("DEBUG: Insufficient balance for transaction, verification failed");
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return Ok(());
            }
        }

        // User transaction and sponsorship tx inclusion
        // Only verify the user tx and the sponsorship tx
        println!("DEBUG: Starting transaction merkle proof verification for Type B");
        assert!(
            preconf_req_b.tx_merkle_proof.len() == 2,
            "Expected 2 merkle proofs (user tx and sponsorship tx), got {}",
            preconf_req_b.tx_merkle_proof.len()
        );

        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        println!("DEBUG: Verifying {} merkle proofs", preconf_req_b.tx_merkle_proof.len());
        for (index, merkle_proof) in preconf_req_b.tx_merkle_proof.iter().enumerate() {
            println!("DEBUG: Verifying merkle proof {}/2", index + 1);
            assert!(
                merkle_proof.root == inclusion_block_header.transactions_root,
                "Merkle proof root mismatch for proof {}: expected {:?}, got {:?}",
                index,
                inclusion_block_header.transactions_root,
                merkle_proof.root
            );

            // Verify the merkle proof
            let node = trie
                .verify_proof(
                    merkle_proof.root,
                    merkle_proof.key.as_slice(),
                    merkle_proof.proof.clone(),
                )?
                .ok_or(eyre::eyre!("Failed to verify merkle proof"))?;

            // Decode the transaction
            let decoded_tx = TxEnvelope::decode_2718(&mut node.as_slice())?;

            if index == 0 {
                // check that the user tx is the first transaction
                assert!(
                    decoded_tx.tx_hash() == tx.tx_hash(),
                    "User transaction hash mismatch: expected {:?}, got {:?}",
                    tx.tx_hash(),
                    decoded_tx.tx_hash()
                );
                println!("DEBUG: Verified user transaction hash");
            } else {
                // check that the sponsorship tx is the second transaction
                assert!(
                    decoded_tx.tx_hash() == preconf_req_b.sponsorship_tx.tx_hash(),
                    "Sponsorship transaction hash mismatch: expected {:?}, got {:?}",
                    preconf_req_b.sponsorship_tx.tx_hash(),
                    decoded_tx.tx_hash()
                );
                println!("DEBUG: Verified sponsorship transaction hash");
            }
        }

        // Sponsorship tx verification (correct smart contract call and data passed)
        println!("DEBUG: Starting sponsorship tx verification");
        let sponsorship_tx = preconf_req_b.sponsorship_tx;

        // Check that the sponsorship tx to field matches the taiyi core address
        let sponsorship_to =
            sponsorship_tx.to().ok_or(eyre::eyre!("Sponsorship tx has no to address"))?;

        // TODO: Check if this is correct (aka. should the sponsorship tx be to the taiyi core address?)
        assert!(
            sponsorship_to == taiyi_core,
            "Sponsorship tx to address mismatch: expected {:?}, got {:?}",
            taiyi_core,
            sponsorship_to
        ); // taiyi core address
        println!("DEBUG: Verified sponsorship tx to address matches taiyi core");

        // Decode the sponsor call
        let sponsor_call = sponsorEthBatchCall::abi_decode(sponsorship_tx.input(), true)?;

        let mut sender_found = false;
        println!("DEBUG: Checking sponsorship for transaction signer");
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            let tx_signer = tx.recover_signer()?;

            if recipient == &tx_signer {
                // TODO: check amount
                println!("DEBUG: Found sponsorship for signer: {:?}", tx_signer);
                sender_found = true;
                break;
            }
        }

        if !sender_found {
            println!("ERROR: No sponsorship found for transaction signer");
            panic!("Sponsorship verification failed: No sponsorship tx for sender");
        }
        println!("DEBUG: Transaction signer is sponsored");
    }

    // Encode the public values of the program.
    println!("DEBUG: Encoding final public values");
    let bytes = PublicValuesStruct {
        proofBlockTimestamp: inclusion_block_header.timestamp,
        proofBlockHash: inclusion_block_hash,
        proofBlockNumber: inclusion_block_header.number,
        underwriterAddress: underwriter_address,
        proofSignature: preconf_signature.as_bytes().to_vec().into(),
        genesisTimestamp: genesis_timestamp,
        taiyiCore: taiyi_core,
    }
    .abi_encode_sequence();

    println!("DEBUG: Committing public values, verification successful");
    // Commit the public values of the program.
    sp1_zkvm::io::commit_slice(&bytes);

    println!("DEBUG: Poi verification completed successfully");
    Ok(())
}

pub fn main() {
    match verify() {
        Err(e) => {
            println!("ERROR: Poi verification failed: {}", e);
            panic!("Poi verification failed: {}", e);
        }
        _ => println!("DEBUG: Poi verification completed successfully"),
    }
}
