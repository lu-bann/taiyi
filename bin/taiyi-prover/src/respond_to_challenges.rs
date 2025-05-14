use std::sync::Arc;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{hex, U256};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_rpc_types::Filter;
use alloy_signer::k256;
use alloy_sol_types::sol;
use eth_trie_proofs::tx_trie::TxsMptHandler;
use futures_util::StreamExt;
use redb::Database;
use reqwest::Url;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};
use taiyi_zkvm_types::types::{AccountMerkleProof, TxMerkleProof};
use tracing::error;

use crate::{table_definitions::PRECONF_DATA_TABLE, Opts};

const ELF_POI: &[u8] = include_elf!("taiyi-poi");

sol! {
    #[sol(rpc)]
    contract TaiyiInteractiveChallenger {
        event ChallengeOpened(
            bytes32 indexed id, address indexed challenger, address indexed commitmentSigner
        );

        function prove(
            bytes32 id,
            bytes calldata proofValues,
            bytes calldata proofBytes
        )
            external;
    }
}

pub async fn respond_to_challenges(
    preconf_db: Arc<Database>,
    opts: Arc<Opts>,
    genesis_timestamp: u64,
) -> eyre::Result<()> {
    // Create a ws provider
    let ws = WsConnect::new(&opts.execution_client_ws_url);
    let provider = match ProviderBuilder::new().on_ws(ws).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create provider: {}", e);
            return Ok(());
        }
    };

    // Initialize signer
    let private_key =
        match hex::decode(opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key)) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to decode private key: {}", e);
                return Ok(());
            }
        };

    let signing_key = match k256::ecdsa::SigningKey::from_slice(&private_key) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to create signing key: {}", e);
            return Ok(());
        }
    };

    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(signing_key);

    // Underwriter address
    let signer_address = private_key_signer.address();

    // Filter for watching for challenge creations
    let filter = Filter::new()
        .address(opts.taiyi_challenger_address)
        .event("ChallengeOpened(bytes32 indexed, address indexed, address indexed)")
        .from_block(BlockNumberOrTag::Latest);

    let subscription = match provider.subscribe_logs(&filter).await {
        Ok(sub) => sub,
        Err(e) => {
            error!("Failed to subscribe to logs: {}", e);
            return Ok(());
        }
    };

    let mut stream = subscription.into_stream();

    while let Some(log) = stream.next().await {
        let challenge_opened_event =
            match log.log_decode::<TaiyiInteractiveChallenger::ChallengeOpened>() {
                Ok(event) => event,
                Err(e) => {
                    error!("Failed to decode challenge opened event: {}", e);
                    continue;
                }
            };

        let challenge_opened = challenge_opened_event.data();

        let challenge_id = challenge_opened.id;
        let challenger = challenge_opened.challenger;
        let commitment_signer = challenge_opened.commitmentSigner;
        let challenge_id_string = challenge_id.to_string();

        println!("Challenge opened: {challenge_id:?}");
        println!("Challenger: {challenger:?}");
        println!("Commitment signer: {commitment_signer:?}");

        if commitment_signer != signer_address {
            println!("Commitment signer is not underwriter, skipping");
            continue;
        }

        println!("Proving challenge...");

        let read_tx = match preconf_db.begin_read() {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to begin read transaction: {}", e);
                continue;
            }
        };

        let table = match read_tx.open_table(PRECONF_DATA_TABLE) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to open PRECONF_DATA_TABLE: {}", e);
                continue;
            }
        };

        let preconf_data = match table.get(&challenge_id_string) {
            Ok(Some(data)) => data,
            Ok(None) => {
                println!("Preconf data not found for challenge id {challenge_id_string}");
                continue;
            }
            Err(e) => {
                error!("Failed to get preconf data: {}", e);
                continue;
            }
        };

        let preconf_request_data = preconf_data.value();

        println!("Preconf request data: {preconf_request_data:?}");

        if preconf_request_data.preconf_type == 0 {
            // Generate proof for Type A
            let preconf_request = match serde_json::from_str::<PreconfRequestTypeA>(
                &preconf_request_data.preconf_request,
            ) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to parse TypeA request: {}", e);
                    continue;
                }
            };

            let mut user_transactions = Vec::new();
            for tx in preconf_request.preconf_tx.iter() {
                let user_transaction = match provider.get_transaction_by_hash(*tx.tx_hash()).await {
                    Ok(Some(tx)) => tx,
                    Ok(None) => {
                        error!("Transaction not found: {:?}", tx.tx_hash());
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to get transaction: {}", e);
                        continue;
                    }
                };
                user_transactions.push(user_transaction);
            }

            let tip_transaction = match provider
                .get_transaction_by_hash(*preconf_request.tip_transaction.tx_hash())
                .await
            {
                Ok(Some(tx)) => tx,
                Ok(None) => {
                    error!(
                        "Tip transaction not found: {:?}",
                        preconf_request.tip_transaction.tx_hash()
                    );
                    continue;
                }
                Err(e) => {
                    error!("Failed to get tip transaction: {}", e);
                    continue;
                }
            };

            let block_number = match tip_transaction.block_number {
                Some(num) => num,
                None => {
                    error!("Tip transaction has no block number");
                    continue;
                }
            };

            let inclusion_block =
                match provider.get_block_by_number(BlockNumberOrTag::Number(block_number)).await {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        error!("Block not found: {}", block_number);
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to get block: {}", e);
                        continue;
                    }
                };

            let previous_block = match provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number - 1))
                .await
            {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("Previous block not found: {}", block_number - 1);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get previous block: {}", e);
                    continue;
                }
            };

            let mut account_proofs = Vec::new();
            for tx in &user_transactions {
                let account_proof = match provider
                    .get_proof(tx.inner.signer(), vec![])
                    .block_id((block_number - 1).into())
                    .await
                {
                    Ok(proof) => proof,
                    Err(e) => {
                        error!("Failed to get account proof: {}", e);
                        continue;
                    }
                };

                account_proofs.push(AccountMerkleProof {
                    address: account_proof.address,
                    nonce: account_proof.nonce,
                    balance: account_proof.balance,
                    storage_hash: account_proof.storage_hash,
                    code_hash: account_proof.code_hash,
                    account_proof: account_proof.account_proof,
                    state_root: previous_block.header.state_root,
                });
            }

            // tx proof
            let url = match Url::parse(&opts.execution_client_url) {
                Ok(url) => url,
                Err(e) => {
                    error!("Failed to parse execution client URL: {}", e);
                    continue;
                }
            };

            let mut txs_mpt_handler = match TxsMptHandler::new(url) {
                Ok(handler) => handler,
                Err(e) => {
                    error!("Failed to create TxsMptHandler: {}", e);
                    continue;
                }
            };

            if let Err(e) = txs_mpt_handler.build_tx_tree_from_block(block_number).await {
                error!("Failed to build tx tree: {}", e);
                continue;
            }

            let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

            // user txs
            for tx in &user_transactions {
                let tx_hash = tx.inner.tx_hash();
                let tx_index = match txs_mpt_handler.tx_hash_to_tx_index(*tx_hash) {
                    Ok(index) => index,
                    Err(e) => {
                        error!("Failed to get tx index: {}", e);
                        continue;
                    }
                };

                let proof = match txs_mpt_handler.get_proof(tx_index) {
                    Ok(proof) => proof,
                    Err(e) => {
                        error!("Failed to get tx proof: {}", e);
                        continue;
                    }
                };

                tx_merkle_proof.push(TxMerkleProof {
                    key: alloy_rlp::encode(U256::from(tx_index)),
                    proof,
                    root: inclusion_block.header.transactions_root,
                });
            }

            // SP1 part
            let mut stdin = SP1Stdin::new();

            // serde serialized preconf request type a
            stdin.write(&preconf_request_data.preconf_request);

            // hex-encoded preconfirmation signature
            stdin.write(&preconf_request_data.preconf_request_signature);

            // is type a
            stdin.write(&true);

            // inclusion block header
            let inclusion_block_header_serialized =
                match serde_json::to_string(&inclusion_block.header) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize inclusion block header: {}", e);
                        continue;
                    }
                };
            stdin.write(&inclusion_block_header_serialized);

            // inclusion block hash
            stdin.write(&inclusion_block.header.hash_slow());

            // previous block header
            let previous_block_header_serialized =
                match serde_json::to_string(&previous_block.header) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize previous block header: {}", e);
                        continue;
                    }
                };
            stdin.write(&previous_block_header_serialized);

            // previous block hash
            stdin.write(&previous_block.header.hash_slow());

            // underwriter address
            stdin.write(&signer_address);

            // genesis time
            stdin.write(&genesis_timestamp);

            // taiyi core address
            stdin.write(&opts.taiyi_challenger_address);

            println!("Using the local/cpu SP1 prover.");
            let client = ProverClient::builder().cpu().build();

            println!("Executing program...");
            let (_, report) = match client.execute(ELF_POI, &stdin).run() {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to execute program: {}", e);
                    continue;
                }
            };
            println!("Executed program with {} cycles", report.total_instruction_count());

            continue;
        }

        // Generate proof for Type B
        let preconf_request = match serde_json::from_str::<PreconfRequestTypeB>(
            &preconf_request_data.preconf_request,
        ) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse TypeB request: {}", e);
                continue;
            }
        };

        let user_transaction = match provider
            .get_transaction_by_hash(
                *preconf_request
                    .transaction
                    .ok_or_else(|| {
                        error!("No transaction in TypeB request");
                        eyre::eyre!("No transaction in TypeB request")
                    })?
                    .tx_hash(),
            )
            .await
        {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                error!("Transaction not found");
                continue;
            }
            Err(e) => {
                error!("Failed to get transaction: {}", e);
                continue;
            }
        };

        let block_number = match user_transaction.block_number {
            Some(num) => num,
            None => {
                error!("Transaction has no block number");
                continue;
            }
        };

        let inclusion_block =
            match provider.get_block_by_number(BlockNumberOrTag::Number(block_number)).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("Block not found: {}", block_number);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get block: {}", e);
                    continue;
                }
            };

        let previous_block =
            match provider.get_block_by_number(BlockNumberOrTag::Number(block_number - 1)).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    error!("Previous block not found: {}", block_number - 1);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get previous block: {}", e);
                    continue;
                }
            };

        // account proof
        let account_proof = match provider
            .get_proof(user_transaction.inner.signer(), vec![])
            .block_id((block_number - 1).into())
            .await
        {
            Ok(proof) => proof,
            Err(e) => {
                error!("Failed to get account proof: {}", e);
                continue;
            }
        };

        let _account_merkle_proof = AccountMerkleProof {
            address: account_proof.address,
            nonce: account_proof.nonce,
            balance: account_proof.balance,
            storage_hash: account_proof.storage_hash,
            code_hash: account_proof.code_hash,
            account_proof: account_proof.account_proof,
            state_root: previous_block.header.state_root,
        };

        // tx proof
        let url = match Url::parse(&opts.execution_client_url) {
            Ok(url) => url,
            Err(e) => {
                error!("Failed to parse execution client URL: {}", e);
                continue;
            }
        };

        let mut txs_mpt_handler = match TxsMptHandler::new(url) {
            Ok(handler) => handler,
            Err(e) => {
                error!("Failed to create TxsMptHandler: {}", e);
                continue;
            }
        };

        if let Err(e) = txs_mpt_handler.build_tx_tree_from_block(block_number).await {
            error!("Failed to build tx tree: {}", e);
            continue;
        }

        let mut tx_merkle_proof: Vec<TxMerkleProof> = Vec::new();

        // user tx
        let tx_hash = user_transaction.inner.tx_hash();
        let tx_index = match txs_mpt_handler.tx_hash_to_tx_index(*tx_hash) {
            Ok(index) => index,
            Err(e) => {
                error!("Failed to get tx index: {}", e);
                continue;
            }
        };

        let proof = match txs_mpt_handler.get_proof(tx_index) {
            Ok(proof) => proof,
            Err(e) => {
                error!("Failed to get tx proof: {}", e);
                continue;
            }
        };

        tx_merkle_proof.push(TxMerkleProof {
            key: alloy_rlp::encode(U256::from(tx_index)),
            proof,
            root: inclusion_block.header.transactions_root,
        });

        // SP1 part
        let mut stdin = SP1Stdin::new();

        // serde serialized preconf request type b
        stdin.write(&preconf_request_data.preconf_request);

        // hex-encoded preconfirmation signature
        stdin.write(&preconf_request_data.preconf_request_signature);

        // is type a
        stdin.write(&false);

        // inclusion block header
        let inclusion_block_header_serialized = match serde_json::to_string(&inclusion_block.header)
        {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize inclusion block header: {}", e);
                continue;
            }
        };
        stdin.write(&inclusion_block_header_serialized);

        // inclusion block hash
        stdin.write(&inclusion_block.header.hash_slow());

        // previous block header
        let previous_block_header_serialized = match serde_json::to_string(&previous_block.header) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize previous block header: {}", e);
                continue;
            }
        };
        stdin.write(&previous_block_header_serialized);

        // previous block hash
        stdin.write(&previous_block.header.hash_slow());

        // underwriter address
        stdin.write(&signer_address);

        // genesis time
        stdin.write(&genesis_timestamp);

        // taiyi core address
        stdin.write(&opts.taiyi_challenger_address);

        println!("Using the local/cpu SP1 prover.");
        let client = ProverClient::builder().cpu().build();

        println!("Executing program...");
        let (_, report) = match client.execute(ELF_POI, &stdin).run() {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to execute program: {}", e);
                continue;
            }
        };
        println!("Executed program with {} cycles", report.total_instruction_count());
    }

    Ok(())
}
