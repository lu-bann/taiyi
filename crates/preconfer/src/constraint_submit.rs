use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::Header;
use alloy_eips::{eip1559::BaseFeeParams, eip2718::Encodable2718, BlockId};
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{hex, keccak256, private::alloy_rlp::Decodable, Bytes, U256};
use alloy_provider::{ext::DebugApi, utils::EIP1559_MIN_PRIORITY_FEE, Provider};
use alloy_rpc_types::TransactionRequest;
use ethereum_consensus::{
    clock::from_system_time, deneb::mainnet::MAX_BYTES_PER_TRANSACTION, primitives::BlsPublicKey,
    ssz::prelude::ByteList,
};
use futures::StreamExt;
use taiyi_primitives::{ConstraintsMessage, PreconfRequest, SignableBLS, SignedConstraints, TxExt};
use tracing::{debug, error, info};

use crate::{
    context_ext::ContextExt,
    contract::{core::TaiyiCore, to_solidity_type},
    error::RpcError,
    preconf_api::state::PreconfState,
};

pub fn spawn_constraint_submitter<P, F>(
    state: PreconfState<P, F>,
) -> impl Future<Output = eyre::Result<()>>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let relay_client = state.relay_client.clone();
    let context = state.network_state.context();
    let chain_id = state.network_state.chain_id();
    info!("Starting constraint submitter, chain_id: {chain_id}");

    async move {
        let clock = from_system_time(
            context.actual_genesis_time(),
            context.seconds_per_slot,
            context.slots_per_epoch,
        );
        let mut slot_stream = clock.into_stream();

        let signer = state.signer_client.ecdsa_signer();
        let wallet = EthereumWallet::from(signer.clone());
        let sender = state.signer_client.ecdsa_address();

        let taiyi_core =
            TaiyiCore::new(state.preconf_pool.taiyi_escrow_address, state.provider.clone());

        while let Some(slot) = slot_stream.next().await {
            let next_slot = slot + 1;

            let submit_constraint_deadline_duration =
                context.get_deadline_of_slot(next_slot).saturating_sub(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs(),
                );

            // calculate base fee for next slot based on parent header
            // Its fine to use latest block as we are submitting constraints for next block
            let rlp_encoded_header = state.provider.debug_get_raw_header(BlockId::latest()).await?;
            let header = Header::decode(&mut rlp_encoded_header.as_ref())?;
            let (base_fee, priority_fee) =
                match header.next_block_base_fee(BaseFeeParams::ethereum()) {
                    Some(base_fee) => (base_fee.into(), EIP1559_MIN_PRIORITY_FEE),
                    None => {
                        let estimate = state.provider.estimate_eip1559_fees(None).await?;
                        (estimate.max_fee_per_gas, estimate.max_priority_fee_per_gas)
                    }
                };
            let blob_fee = header.next_block_blob_fee().unwrap_or_default();
            let blob_excess_fee = header.next_block_excess_blob_gas().unwrap_or_default();

            // wait unit the deadline to submit constraints
            tokio::time::sleep(Duration::from_secs(submit_constraint_deadline_duration)).await;

            info!(base_fee=?base_fee, priority_fee=?priority_fee, blob_fee=?blob_fee, blob_excess_fee=?blob_excess_fee);

            let mut constraints = Vec::new();
            let mut sponsoring_tx = Vec::new();
            let mut type_a_txs = Vec::new();
            let mut type_b_txs = Vec::new();
            let mut exhaust_txs = Vec::new();

            let mut nonce = state.provider.get_transaction_count(sender).await?;
            // Accounts to sponsor gas for
            let mut accounts = Vec::new();
            // Amounts to sponsor for each account
            let mut amounts = Vec::new();

            let mut cummalative_preconf_tips = U256::ZERO;
            let fee_reciepient =
                state.network_state.get_fee_recipient(next_slot).unwrap_or_default();
            info!(fee_reciepient=?fee_reciepient);

            match state.preconf_pool.fetch_ready(next_slot) {
                Ok(preconf_requests) => {
                    let sponsor_nonce = nonce;
                    nonce += 1;
                    for preconf_req in preconf_requests {
                        cummalative_preconf_tips += preconf_req.preconf_tip();
                        match preconf_req {
                            PreconfRequest::TypeA(request) => {
                                let tip_tx_gas_uesd = state
                                    .preconf_pool
                                    .calculate_gas_used(request.tip_transaction.clone())
                                    .await?;
                                let mut preconf_tx_gas_used: u64 = 0;
                                for preconf_tx in request.preconf_tx.clone() {
                                    let gas_used =
                                        state.preconf_pool.calculate_gas_used(preconf_tx).await?;
                                    preconf_tx_gas_used += gas_used;
                                }

                                accounts.push(request.signer());
                                amounts.push(U256::from(
                                    (tip_tx_gas_uesd + preconf_tx_gas_used) as u128 * base_fee,
                                ));

                                let tx_bytes = request.tip_transaction.to_ssz_bytes();
                                type_a_txs.push(tx_bytes);

                                for preconf_tx in request.preconf_tx {
                                    let tx_bytes = preconf_tx.to_ssz_bytes();
                                    type_a_txs.push(tx_bytes);
                                }
                            }
                            PreconfRequest::TypeB(preconf_req) => {
                                if let Some(ref tx) = preconf_req.transaction {
                                    // calculate gas used
                                    let gas_used =
                                        state.preconf_pool.calculate_gas_used(tx.clone()).await?;

                                    accounts.push(preconf_req.signer());
                                    amounts.push(U256::from(gas_used as u128 * base_fee));

                                    // preconf tx
                                    let mut tx_encoded = Vec::new();
                                    tx.encode_2718(&mut tx_encoded);
                                    let tx_ref: &[u8] = tx_encoded.as_ref();
                                    let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                                        tx_ref.try_into().expect("tx bytes too big");
                                    type_b_txs.push(tx_bytes);

                                    // Append with a transaction that calls get_tip() on TaiyiCore contract
                                    let blockspace_allocation_sig_user = preconf_req.alloc_sig;
                                    let blockspace_allocation_sig_gateway = state
                                        .signer_client
                                        .sign_with_ecdsa(keccak256(
                                            blockspace_allocation_sig_user.as_bytes(),
                                        ))
                                        .await
                                        .map_err(|e| RpcError::SignatureError(format!("{e:?}")))?;
                                    let raw_tx = format!("0x{}", hex::encode(&tx_encoded));
                                    let gateway_signed_raw_tx = state
                                        .signer_client
                                        .sign_with_ecdsa(keccak256(raw_tx))
                                        .await
                                        .map_err(|e| {
                                            RpcError::SignatureError(format!(
                                                "Failed to issue commitment: {e:?}"
                                            ))
                                        })?;
                                    let preconf_request_type_b = to_solidity_type(
                                        preconf_req,
                                        blockspace_allocation_sig_user,
                                        blockspace_allocation_sig_gateway,
                                        tx_encoded.into(),
                                        gateway_signed_raw_tx,
                                    );

                                    // Call getTip() on TaiyiCore contract
                                    let get_tip_tx = taiyi_core
                                        .getTip(preconf_request_type_b)
                                        .into_transaction_request()
                                        .with_chain_id(chain_id)
                                        .with_nonce(nonce)
                                        .with_gas_limit(1_000_000)
                                        .with_max_fee_per_gas(base_fee)
                                        .with_max_priority_fee_per_gas(priority_fee)
                                        .build(&wallet)
                                        .await?;
                                    // increment nonce
                                    nonce += 1;
                                    let tx_bytes = get_tip_tx.to_ssz_bytes();
                                    type_b_txs.push(tx_bytes);
                                }
                            }
                        }
                    }

                    //  gas sponsorship tx
                    let sponsor_tx = taiyi_core
                        .sponsorEthBatch(accounts, amounts)
                        .into_transaction_request()
                        .with_nonce(sponsor_nonce)
                        .with_chain_id(chain_id)
                        .with_gas_limit(1_000_000)
                        .with_max_fee_per_gas(base_fee)
                        .with_max_priority_fee_per_gas(priority_fee)
                        .build(&wallet)
                        .await?;
                    let tx_bytes = sponsor_tx.to_ssz_bytes();
                    sponsoring_tx.push(tx_bytes);

                    // Validator Payout Transaction
                    let value = cummalative_preconf_tips;
                    let validator_payout_tx = TransactionRequest::default()
                        .with_nonce(nonce)
                        .with_chain_id(chain_id)
                        .with_gas_limit(21_000)
                        .with_max_fee_per_gas(base_fee)
                        .with_max_priority_fee_per_gas(priority_fee)
                        .with_to(fee_reciepient)
                        .with_value(value)
                        .build(&wallet)
                        .await?;
                    let tx_bytes = validator_payout_tx.to_ssz_bytes();
                    type_b_txs.push(tx_bytes);
                }
                Err(err) => {
                    debug!(?err, "Error fetching preconf requests for slot");
                }
            }

            // Fetch all preconf requests for which the gateway must call exhaust() on TaiyiCore contract
            match state.preconf_pool.fetch_pending(next_slot) {
                Ok(requests) => {
                    info!(
                        "Found {} preconf requests for slot {} to be exhausted",
                        requests.len(),
                        next_slot
                    );

                    for preconf_req in requests {
                        let blockspace_allocation_sig_user = preconf_req.alloc_sig;
                        let blockspace_allocation_sig_gateway = state
                            .signer_client
                            .sign_with_ecdsa(keccak256(blockspace_allocation_sig_user.as_bytes()))
                            .await
                            .map_err(|e| RpcError::SignatureError(format!("{e:?}")))?;
                        let preconf_request_type_b = to_solidity_type(
                            preconf_req,
                            blockspace_allocation_sig_user,
                            blockspace_allocation_sig_gateway,
                            Bytes::default(),
                            state
                                .signer_client
                                // Empty raw tx
                                .sign_with_ecdsa(keccak256(Bytes::default()))
                                .await
                                .map_err(|e| {
                                    RpcError::SignatureError(format!(
                                        "Failed to issue commitment: {e:?}"
                                    ))
                                })?,
                        );

                        // Call exhaust() on TaiyiCore contract
                        let exhaust_tx = taiyi_core
                            .exhaust(preconf_request_type_b)
                            .into_transaction_request()
                            .with_chain_id(chain_id)
                            .with_nonce(nonce)
                            .with_gas_limit(1_000_000)
                            .with_max_fee_per_gas(base_fee)
                            .with_max_priority_fee_per_gas(priority_fee)
                            .build(&wallet)
                            .await?;
                        // increment nonce
                        nonce += 1;

                        let tx_bytes = exhaust_tx.to_ssz_bytes();
                        exhaust_txs.push(tx_bytes);
                    }
                }
                Err(err) => {
                    debug!(?err, "Error fetching preconf requests for slot");
                }
            }

            constraints.extend(sponsoring_tx);
            constraints.extend(type_a_txs);
            constraints.extend(type_b_txs);
            constraints.extend(exhaust_txs);

            let txs_len = constraints.len();
            if txs_len != 0 {
                let bls_pk = state.signer_client.bls_pubkey();
                let message = ConstraintsMessage {
                    pubkey: BlsPublicKey::try_from(bls_pk.to_bytes().as_ref()).expect("key error"),
                    slot: next_slot,
                    top: false,
                    transactions: constraints.try_into().expect("tx too big"),
                };
                let digest = message.digest();
                if let Ok(signature) = state.signer_client.sign_with_bls(context.clone(), digest) {
                    let signed_constraints_message = vec![SignedConstraints { message, signature }];

                    let max_retries = 5;
                    let mut i = 0;

                    info!("Submitting {txs_len} constraints to relay on  slot {next_slot}");
                    'submit: while let Err(e) =
                        relay_client.set_constraints(signed_constraints_message.clone()).await
                    {
                        error!(err = ?e, "Error submitting constraints to relay, retrying...");
                        i += 1;
                        if i >= max_retries {
                            error!("Max retries reached while submitting to relay");
                            break 'submit;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        Ok(())
    }
}
