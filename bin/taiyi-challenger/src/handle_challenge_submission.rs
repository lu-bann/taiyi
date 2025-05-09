use std::sync::Arc;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_signer::k256::{self};
use alloy_sol_types::sol;
use futures_util::StreamExt;
use redb::Database;
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};
use tracing::{debug, error};

use crate::{get_slot_from_timestamp, table_definitions::CHALLENGE_TABLE, Opts};

sol! {
    #[sol(rpc)]
    contract TaiyiInteractiveChallenger {
        #[derive(Debug)]
        struct PreconfRequestAType {
            string[] txs;
            string tipTx;
            uint256 slot;
            uint256 sequenceNum;
            address signer;
        }

        #[derive(Debug)]
        struct BlockspaceAllocation {
            uint256 gasLimit;
            address sender;
            address recipient;
            uint256 deposit;
            uint256 tip;
            uint256 targetSlot;
            uint256 blobCount;
        }

        #[derive(Debug)]
        struct PreconfRequestBType {
            BlockspaceAllocation blockspaceAllocation;
            bytes blockspaceAllocationSignature;
            bytes underwriterSignedBlockspaceAllocation;
            bytes rawTx;
            bytes underwriterSignedRawTx;
        }


        #[derive(Debug)]
        function createChallengeAType(
            PreconfRequestAType calldata preconfRequestAType,
            bytes calldata signature
        )
            external
            payable;

        #[derive(Debug)]
        function createChallengeBType(
            PreconfRequestBType calldata preconfRequestBType,
            bytes calldata signature
        )
            external
            payable;

            #[derive(Debug)]
        function resolveExpiredChallenge(bytes32 id) external;
    }
}

pub async fn handle_challenge_submission(
    challenge_db: Arc<Database>,
    opts: Arc<Opts>,
    genesis_timestamp: u64,
) -> eyre::Result<()> {
    // Initialize signer
    let private_key_bytes =
        match hex::decode(opts.private_key.strip_prefix("0x").unwrap_or(&opts.private_key)) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to decode private key: {}", e);
                return Err(eyre::eyre!("Failed to decode private key: {}", e));
            }
        };

    let signing_key = match k256::ecdsa::SigningKey::from_slice(&private_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            error!("[Challenger Submitter]: Failed to create signing key: {}", e);
            return Err(eyre::eyre!("Failed to create signing key: {}", e));
        }
    };

    let private_key_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(signing_key);
    let signer_address = private_key_signer.address();

    debug!("[Challenger Submitter]: Signer address: {}", signer_address);

    let ws = WsConnect::new(&opts.execution_client_ws_url);
    let provider = match ProviderBuilder::new().wallet(private_key_signer).on_ws(ws).await {
        Ok(p) => p,
        Err(e) => {
            error!("[Challenger Submitter]: Failed to create provider with wallet: {}", e);
            return Err(eyre::eyre!("Failed to create provider with wallet: {}", e));
        }
    };

    // Check balance to verify signer is working correctly
    match provider.get_balance(signer_address).await {
        Ok(balance) => {
            debug!("[Challenger Submitter]: Signer ETH balance: {}", balance);
        }
        Err(e) => {
            error!("[Challenger Submitter]: Failed to get signer balance: {}", e);
            // Continue anyway, this is not critical
        }
    };

    let taiyi_challenger =
        TaiyiInteractiveChallenger::new(opts.taiyi_challenger_address, provider.clone());

    let subscription = match provider.subscribe_blocks().await {
        Ok(sub) => sub,
        Err(e) => {
            error!("[Challenger Submitter]: Failed to subscribe to blocks: {}", e);
            return Err(eyre::eyre!("Failed to subscribe to blocks: {}", e));
        }
    };

    let mut stream = subscription.into_stream();

    while let Some(header) = stream.next().await {
        debug!("[Challenger Submitter]: Processing block {:?}", header.number);
        let slot = get_slot_from_timestamp(header.timestamp, genesis_timestamp);
        debug!("[Challenger Submitter]: Slot: {:?}", slot);

        // Check if challenges exists for the slot
        let read_tx = match challenge_db.begin_read() {
            Ok(tx) => tx,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to begin read transaction: {}", e);
                continue;
            }
        };

        let table = match read_tx.open_table(CHALLENGE_TABLE) {
            Ok(table) => table,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to open challenge table: {}", e);
                continue;
            }
        };

        let challenges = table.get(&slot);

        if challenges.is_err() {
            error!(
                "[Challenger Submitter]: Storage error for slot {}. Error: {:?}",
                slot,
                challenges.err()
            );
            continue;
        }

        let challenges_result = match challenges {
            Ok(result) => result,
            Err(e) => {
                error!("[Challenger Submitter]: Failed to get challenges: {}", e);
                continue;
            }
        };

        if challenges_result.is_none() {
            // No challenges found for the slot
            debug!("[Challenger Submitter]: No challenges found for slot {}", slot);
            continue;
        }

        let challenges_data = match challenges_result {
            Some(values) => values.value(),
            None => {
                debug!("[Challenger Submitter]: No challenges found for slot {}", slot);
                continue;
            }
        };

        debug!(
            "[Challenger Submitter]: Found {} challenges for slot {}",
            challenges_data.len(),
            slot
        );

        // For each challenge, check if the challenge is expired
        for challenge in challenges_data {
            if challenge.preconf_type == 0 {
                // Type A
                let preconf_request =
                    match serde_json::from_str::<PreconfRequestTypeA>(&challenge.preconf_request) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(
                                "[Challenger Submitter]: Failed to parse PreconfRequestTypeA: {}",
                                e
                            );
                            continue;
                        }
                    };

                let mut txs: Vec<String> = Vec::new();

                for tx in preconf_request.preconf_tx {
                    let mut tx_bytes = Vec::new();
                    tx.encode_2718(&mut tx_bytes);
                    let hex_encoded_tx = format!("0x{}", hex::encode(&tx_bytes));
                    txs.push(hex_encoded_tx);
                }

                let mut tip_tx = Vec::new();
                preconf_request.tip_transaction.encode_2718(&mut tip_tx);
                let tip_tx_raw = format!("0x{}", hex::encode(&tip_tx));

                let sequence_number = match preconf_request.sequence_number {
                    Some(num) => num,
                    None => {
                        error!("[Challenger Submitter]: Missing sequence number in PreconfRequestTypeA");
                        continue;
                    }
                };

                let preconf_request_a_type = TaiyiInteractiveChallenger::PreconfRequestAType {
                    txs,
                    tipTx: tip_tx_raw,
                    slot: U256::from(slot),
                    sequenceNum: U256::from(sequence_number),
                    signer: preconf_request.signer,
                };

                // Decode signature
                let signature_bytes = match hex::decode(&challenge.preconf_request_signature) {
                    Ok(bytes) => Bytes::from(bytes),
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to decode signature: {}", e);
                        continue;
                    }
                };

                // Submit challenge to the contract
                debug!("[Challenger Submitter]: Submitting challenge type A for slot {}", slot);
                match taiyi_challenger
                    .createChallengeAType(preconf_request_a_type, signature_bytes)
                    .send()
                    .await
                {
                    Ok(tx) => {
                        debug!("[Challenger Submitter]: Challenge type A submitted. TX: {:?}", tx);
                    }
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to create challenge type A: {}", e);
                        // Continue to next challenge, we may be able to submit others
                    }
                }
            } else {
                // Type B
                let preconf_request =
                    match serde_json::from_str::<PreconfRequestTypeB>(&challenge.preconf_request) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(
                                "[Challenger Submitter]: Failed to parse PreconfRequestTypeB: {}",
                                e
                            );
                            continue;
                        }
                    };

                let transaction = match &preconf_request.transaction {
                    Some(tx) => tx,
                    None => {
                        error!(
                            "[Challenger Submitter]: Missing transaction in PreconfRequestTypeB"
                        );
                        continue;
                    }
                };

                let mut tx_bytes = Vec::new();
                transaction.encode_2718(&mut tx_bytes);
                let tx_raw = format!("0x{}", hex::encode(&tx_bytes));

                let preconf_request_b_type = TaiyiInteractiveChallenger::PreconfRequestBType {
                    blockspaceAllocation: TaiyiInteractiveChallenger::BlockspaceAllocation {
                        gasLimit: U256::from(preconf_request.allocation.gas_limit),
                        sender: preconf_request.allocation.sender,
                        recipient: preconf_request.allocation.recipient,
                        deposit: U256::from(preconf_request.allocation.deposit),
                        tip: U256::from(preconf_request.allocation.tip),
                        targetSlot: U256::from(preconf_request.allocation.target_slot),
                        blobCount: U256::from(preconf_request.allocation.blob_count),
                    },
                    blockspaceAllocationSignature: preconf_request.alloc_sig.as_bytes().into(),
                    rawTx: Bytes::from(tx_raw),
                    // TODO: Can we remove this two fields ?
                    underwriterSignedBlockspaceAllocation: Bytes::from([]),
                    underwriterSignedRawTx: Bytes::from([]),
                };

                // Decode signature
                let signature_bytes = match hex::decode(&challenge.preconf_request_signature) {
                    Ok(bytes) => Bytes::from(bytes),
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to decode signature: {}", e);
                        continue;
                    }
                };

                // Submit challenge to the contract
                debug!("[Challenger Submitter]: Submitting challenge type B for slot {}", slot);
                match taiyi_challenger
                    .createChallengeBType(preconf_request_b_type, signature_bytes)
                    .send()
                    .await
                {
                    Ok(tx) => {
                        debug!("[Challenger Submitter]: Challenge type B submitted. TX: {:?}", tx);
                    }
                    Err(e) => {
                        error!("[Challenger Submitter]: Failed to create challenge type B: {}", e);
                        // Continue to next challenge, we may be able to submit others
                    }
                }
            }
        }

        debug!("[Challenger Submitter]: Processed block {:?}", header.number);
    }

    Ok(())
}
