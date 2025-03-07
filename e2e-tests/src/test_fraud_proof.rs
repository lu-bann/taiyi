use std::str::FromStr;

use alloy_consensus::{Account, Transaction};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{hex, Bytes, PrimitiveSignature, B256, U256};
use alloy_provider::{ext::DebugApi, network::EthereumWallet, Provider, ProviderBuilder};
use alloy_rpc_types::{BlockTransactions, BlockTransactionsKind};
use alloy_sol_types::SolCall;
use eth_trie_proofs::tx_trie::TxsMptHandler;
use ethereum_consensus::{crypto::PublicKey as BlsPublicKey, ssz::prelude::ssz_rs};
use reqwest::Url;
use sp1_sdk::{include_elf, SP1Stdin};
use taiyi_primitives::PreconfResponse;
use taiyi_zkvm_types::types::{
    AccountMerkleProof, BlockspaceAllocation, PreconfRequestTypeB, PreconfTypeB, TxMerkleProof,
};
use tracing::info;
use uuid::Uuid;

use crate::{
    constant::{PRECONFER_BLS_PK, PRECONFER_ECDSA_SK},
    contract_call::{taiyi_balance, taiyi_deposit},
    utils::{
        generate_reserve_blockspace_request, generate_submit_transaction_request, generate_tx,
        getTipCall, get_available_slot, get_constraints_from_relay, get_preconf_fee, new_account,
        send_reserve_blockspace_request, send_submit_transaction_request, setup_env,
        wait_until_deadline_of_slot, PreconfTypeBJson,
    },
};

const ELF_POI: &[u8] = include_elf!("taiyi-poi");
const ELF_PONI: &[u8] = include_elf!("taiyi-poni");

// TODO: type A included test
// TODO: type A not included test, can be dynamic

#[tokio::test]
#[ignore]
async fn poi_preconf_type_b_included() -> eyre::Result<()> {
    let preconf = PreconfTypeBJson::from_file("testdata/preconf_type_b.json").unwrap();

    let (_taiyi_handle, config) = setup_env().await?;

    let signer = new_account(&config).await?;
    let wallet = EthereumWallet::new(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&config.execution_url)
        .await?;

    let user_transaction = provider
        .get_transaction_by_hash(B256::from_str(&preconf.user_transaction_hash).unwrap())
        .await?
        .unwrap();
    let get_tip_transaction = provider
        .get_transaction_by_hash(B256::from_str(&preconf.gateway_get_tip_transaction_hash).unwrap())
        .await?
        .unwrap();
    let sponsorship_transaction = provider
        .get_transaction_by_hash(
            B256::from_str(&preconf.gateway_sponsorship_transaction_hash).unwrap(),
        )
        .await?
        .unwrap();

    let target_slot = preconf.slot.parse::<u64>()?;

    let inclusion_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(target_slot), BlockTransactionsKind::Full)
        .await?
        .unwrap();

    let previous_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(target_slot - 1), BlockTransactionsKind::Full)
        .await?
        .unwrap();

    let get_tip_call = getTipCall::abi_decode(get_tip_transaction.input(), true).unwrap();

    // account proof

    let account_proof = provider
        .get_proof(user_transaction.from, vec![])
        .block_id((target_slot - 1).into())
        .await?;
    let account_merkle_proof = AccountMerkleProof {
        address: account_proof.address,
        nonce: account_proof.nonce,
        balance: account_proof.balance,
        storage_hash: account_proof.storage_hash,
        code_hash: account_proof.code_hash,
        account_proof: account_proof.account_proof,
        state_root: previous_block.header.state_root,
    };

    // tx proof
    let url = Url::parse(&config.execution_url).unwrap();
    let mut txs_mpt_handler = TxsMptHandler::new(url).unwrap();
    txs_mpt_handler.build_tx_tree_from_block(target_slot).await.unwrap();

    let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

    // user tx
    let tx_hash = user_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
    tx_merkle_proof.push(TxMerkleProof {
        key: tx_hash.as_slice().to_vec(),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // sponsorship tx
    let tx_hash = sponsorship_transaction.inner.tx_hash();
    let tx_index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash.clone()).unwrap();
    let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
    tx_merkle_proof.push(TxMerkleProof {
        key: tx_hash.as_slice().to_vec(),
        proof,
        root: inclusion_block.header.transactions_root,
    });

    // sp1

    let mut stdin = SP1Stdin::new();

    // preconf type b
    let preconf_b = PreconfRequestTypeB {
        allocation: BlockspaceAllocation {
            target_slot: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .targetSlot
                .try_into()
                .unwrap(),
            gas_limit: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .gasLimit
                .try_into()
                .unwrap(),
            deposit: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .deposit
                .try_into()
                .unwrap(),
            tip: get_tip_call.preconfRequestBType.blockspaceAllocation.tip.try_into().unwrap(),
            blob_count: get_tip_call
                .preconfRequestBType
                .blockspaceAllocation
                .blobCount
                .try_into()
                .unwrap(),
        },
        alloc_sig: PrimitiveSignature::from_str(
            &get_tip_call.preconfRequestBType.blockspaceAllocationSignature.to_string(),
        )
        .unwrap(),
        transaction: user_transaction.into(),
        preconf_sig: PrimitiveSignature::from_str(&preconf.preconf_gateway_signature).unwrap(),
    };
    let preconf_type_b = PreconfTypeB {
        preconf: preconf_b,
        sponsorship_tx: sponsorship_transaction.into(),
        tx_merkle_proof,
        account_merkle_proof,
    };
    stdin.write(&preconf_type_b);

    // is type a
    stdin.write(&false);

    // inclusion block header
    stdin.write(&inclusion_block.header);

    // inclusion block hash
    stdin.write(&inclusion_block.header.hash_slow());

    // previous block header
    stdin.write(&previous_block.header);

    // previous block hash
    stdin.write(&previous_block.header.hash_slow());

    // gateway address
    stdin.write(&preconf.gateway_address);

    // TODO: proof generation and proof verification

    Ok(())
}

// TODO: finish not included, can be dynamic
// #[tokio::test]
// async fn poi_preconf_type_b_not_included() -> eyre::Result<()> {
//     let (taiyi_handle, config) = setup_env().await?;

//     let signer = new_account(&config).await?;
//     let wallet = EthereumWallet::new(signer.clone());
//     let provider = ProviderBuilder::new()
//         .with_recommended_fillers()
//         .wallet(wallet.clone())
//         .on_builtin(&config.execution_url)
//         .await?;

//     taiyi_deposit(provider.clone(), 1_000_000_000_000_000).await?;
//     let balance = taiyi_balance(provider.clone(), signer.address()).await?;
//     assert_eq!(balance, U256::from(1_000_000_000_000_000u64));

//     // let available_slot = get_available_slot(&config.taiyi_url()).await?;

//     let target_slot = 155463;
//     info!("Target slot: {:?}", target_slot);

//     let fee = get_preconf_fee(&config.taiyi_url(), target_slot).await?;

//     // Generate request and signature
//     let (blockspace, blockspace_sig) =
//         generate_reserve_blockspace_request(signer.clone(), target_slot, 21_000, 0, fee).await;

//     // Reserve blockspace
//     let res = send_reserve_blockspace_request(
//         blockspace.clone(),
//         blockspace_sig.clone(),
//         &config.taiyi_url(),
//     )
//     .await?;
//     let status = res.status();
//     let body = res.bytes().await?;
//     info!("reserve_blockspace response: {:?}", body);

//     let request_id = serde_json::from_slice::<Uuid>(&body)?;
//     assert_eq!(status, 200);

//     let transaction = generate_tx(&config.execution_url, PRECONFER_ECDSA_SK).await.unwrap();
//     let (request, signature) =
//         generate_submit_transaction_request(signer.clone(), transaction.clone(), request_id).await;

//     let res =
//         send_submit_transaction_request(request.clone(), signature, &config.taiyi_url()).await?;
//     let status = res.status();
//     assert_eq!(status, 200);
//     let body = res.bytes().await?;
//     info!("submit transaction response: {:?}", body);
//     let preconf_response: PreconfResponse = serde_json::from_slice(&body)?;
//     assert_eq!(preconf_response.data.request_id, request_id);

//     // TODO: verify the commitment signature with gateway pub key

//     wait_until_deadline_of_slot(&config, target_slot).await?;

//     let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;
//     let mut txs = Vec::new();
//     for constraint in constraints.iter() {
//         let message = constraint.message.clone();
//         let decoded_txs = message.decoded_tx().unwrap();
//         txs.extend(decoded_txs);
//     }
//     assert_eq!(txs.len(), 3);

//     // let signed_constraints = constraints.first().unwrap().clone();
//     // let message = signed_constraints.message;

//     // let user_tx = txs.get(1).unwrap();

//     // let constraints_data = taiyi_primitives::ConstraintsData::try_from(message.clone()).unwrap();
//     // let constraints_data = ConstraintsData {
//     //     transactions: constraints_data.transactions,
//     //     proof_data: constraints_data.proof_data,
//     // };

//     // // let constraints_data: Vec<ConstraintsData> = constraints
//     // //     .iter()
//     // //     .map(|c| {
//     // //         let data = taiyi_primitives::ConstraintsData::try_from(c.message.clone()).unwrap();
//     // //         return ConstraintsData {
//     // //             transactions: data.transactions,
//     // //             proof_data: data.proof_data,
//     // //         };
//     // //     })
//     // //     .collect::<Vec<_>>();

//     // let inclusion_block = provider
//     //     .get_block_by_number(BlockNumberOrTag::Number(target_slot), BlockTransactionsKind::Full)
//     //     .await?
//     //     .unwrap();

//     // let previous_block = provider
//     //     .get_block_by_number(BlockNumberOrTag::Number(target_slot - 1), BlockTransactionsKind::Full)
//     //     .await?
//     //     .unwrap();

//     // let is_type_a = false;
//     // let inclusion_block_header = inclusion_block.header;
//     // let inclusion_block_hash = inclusion_block_header.hash;
//     // let previous_block_header = previous_block.header;
//     // let previous_block_hash = previous_block_header.hash;
//     // let gateway_address = ""; // TODO: get gateway address

//     // // TODO: TxMerkleMultiProof - https://github.com/ralexstokes/ssz-rs/blob/main/ssz-rs/src/merkleization/proofs.rs

//     // let inclusion_proofs = InclusionProofs {
//     //     transaction_hashes: txs.iter().map(|tx| tx.tx_hash().clone()).collect::<Vec<_>>(), /* TODO: Verify this is correct */
//     //     generalized_indexes: vec![], // TODO: fill this
//     //     merkle_hashes: vec![],       // TODO: fill this
//     // };

//     // let tx_merkle_proof = TxMerkleMultiProof {
//     //     constraints: constraints_data,
//     //     root: inclusion_block_header.transactions_root,
//     //     proofs: inclusion_proofs,
//     // };

//     // // TODO: AccountMerkleProof - https://github.com/alloy-rs/trie
//     // let account_merkle_proof = AccountMerkleProof {
//     //     state_root: inclusion_block_header.state_root,
//     //     address: transaction.recover_signer().unwrap(), // TODO: Verify this is correct

//     //     nonce: 0,                 // TODO: fill this
//     //     balance: U256::from(0),   // TODO: fill this
//     //     storage_hash: B256::ZERO, // TODO: fill this
//     //     code_hash: B256::ZERO,    // TODO: fill this
//     //     account_proof: vec![],    // TODO: fill this
//     // };

//     // // let preconf_request_type_b = PreconfRequestTypeB {
//     // //     req: PreconfRequest {
//     // //         allocation: BlockspaceAllocation {
//     // //             target_slot: blockspace.target_slot,
//     // //             gas_limit: blockspace.gas_limit,
//     // //             deposit: blockspace.deposit,
//     // //             tip: blockspace.tip,
//     // //             blob_count: blockspace.blob_count,
//     // //         },
//     // //         alloc_sig: PrimitiveSignature::from_str(blockspace_sig.as_str()).unwrap(),
//     // //         transaction: Some(user_tx.clone()),
//     // //         signer: user_tx.recover_signer().ok(),
//     // //     },
//     // //     tx_sig: preconf_response.data.commitment.unwrap(),
//     // //     // tx_merkle_proof,
//     // //     // account_merkle_proof,
//     // // };

//     // // Write SP1 inputs
//     // let mut stdin = SP1Stdin::new();
//     // // stdin.write(&preconf_request_type_b);
//     // stdin.write(&is_type_a);
//     // stdin.write(&inclusion_block_header);
//     // stdin.write(&inclusion_block_hash);
//     // stdin.write(&previous_block_header);
//     // stdin.write(&previous_block_hash);
//     // stdin.write(&gateway_address);

//     // // TODO: We probably need to include the signed constraints in the SP1 inputs
//     // // stdin.write(...);

//     // // TODO: create SP1 proof
//     // // TODO: Verify proof

//     // assert_eq!(
//     //     message.pubkey,
//     //     BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
//     // );

//     // assert_eq!(message.slot, target_slot);

//     // assert_eq!(*user_tx, request.transaction);

//     taiyi_handle.abort();

//     Ok(())
// }
