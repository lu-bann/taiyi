use std::{num::TryFromIntError, sync::Arc, time::Duration};

use alloy_consensus::TxEnvelope;
use alloy_eips::{
    eip1559::BaseFeeParams, eip1898::BlockNumberOrTag, eip2718::Encodable2718, eip7840::BlobParams,
    BlockId,
};
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{keccak256, Bytes, Signature, U256};
use alloy_provider::ext::DebugApi;
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_beacon::relay::Validator;
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use futures::{pin_mut, stream::Stream, StreamExt};
use reqwest::Client;
use taiyi_contracts::{TaiyiEscrow, TaiyiEscrowInstance};
use taiyi_crypto::bls::{bls_pubkey_to_alloy, bls_signature_to_alloy};
use taiyi_primitives::{
    constraints::{ConstraintsMessage, SignableBLS, SignedConstraints},
    encode_util::hex_encode,
    PreconfRequest, PreconfRequestTypeB,
};
use tokio::{
    sync::RwLock,
    time::{interval_at, Instant},
};
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, error, info};

use crate::bls_signer::BlsSigner;
use crate::tx_cache::TxCachePerSlot;

pub fn get_next_slot_start(
    now_since_start: &Duration,
    slot_time: &Duration,
) -> Result<Instant, TryFromIntError> {
    let in_last_slot_ms: Duration =
        Duration::from_millis((now_since_start.as_millis() % slot_time.as_millis()).try_into()?);
    let remaining =
        if in_last_slot_ms.is_zero() { Duration::ZERO } else { *slot_time - in_last_slot_ms };
    Ok(Instant::now() + remaining)
}

pub fn get_slot_stream(
    start: Instant,
    next_slot_count: u64,
    slot_time: Duration,
) -> Result<impl Stream<Item = u64>, TryFromIntError> {
    let mut interval = interval_at(start, slot_time);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut next_slot_count = next_slot_count;

    Ok(IntervalStream::new(interval).map(move |_| {
        let slot_count = next_slot_count;
        next_slot_count += 1;

        slot_count
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn submit_constraints<P: Provider>(
    taiyi_escrow: TaiyiEscrowInstance,
    slot_stream: impl Stream<Item = u64>,
    provider: P,
    tx_cache: Arc<RwLock<TxCachePerSlot>>,
    signer: PrivateKeySigner,
    bls_signer: BlsSigner,
    constraints_url: String,
    slots_per_epoch: u64,
) -> eyre::Result<()> {
    let sender = signer.address();
    let chain_id = provider.get_chain_id().await?;
    println!("CHAIN ID: {}", chain_id);

    let wallet = EthereumWallet::from(signer.clone());

    pin_mut!(slot_stream);
    while let Some(slot) = slot_stream.next().await {
        println!("New slot {:?}", slot);
        let next_slot = slot + 1;
        let is_new_epoch = slot % slots_per_epoch == 0;

        let estimate = provider.estimate_eip1559_fees().await?;
        let max_fee_per_gas = estimate.max_fee_per_gas;
        let max_priority_fee_per_gas = estimate.max_priority_fee_per_gas;
        println!("gas estimate {max_fee_per_gas} {max_priority_fee_per_gas}");

        let block = provider.get_block_by_number(BlockNumberOrTag::Latest).await?;
        let header = block.expect("Failed to retrieve latest block").header;

        let base_fee =
            header.next_block_base_fee(BaseFeeParams::ethereum()).unwrap_or(max_fee_per_gas as u64);
        println!("base fee {}", base_fee);

        let blob_fee = header.next_block_blob_fee(BlobParams::prague()).unwrap_or_default();
        let blob_excess_fee =
            header.next_block_excess_blob_gas(BlobParams::prague()).unwrap_or_default();

        info!(base_fee=?base_fee, blob_fee=?blob_fee, blob_excess_fee=?blob_excess_fee);

        let mut reserve_with_calldata_bytes = Vec::new();
        let mut reserve_without_calldata_bytes = Vec::new();

        let mut nonce = provider.get_transaction_count(sender).await?;
        let mut accounts = Vec::new();
        let mut amounts = Vec::new();

        let mut total_preconf_tips = U256::ZERO;

        let (ready, pending) = tx_cache.write().await.take(next_slot).await?;
        let sponsor_nonce = nonce;
        nonce += 1;
        for preconf_req in ready {
            total_preconf_tips += preconf_req.preconf_tip();
            let mut gas = 0u64;
            accounts.push(preconf_req.signer());
            match preconf_req {
                PreconfRequest::TypeA(request) => {
                    gas = gas_used(&provider, request.tip_transaction.clone()).await?;
                    for preconf_tx in request.preconf_tx.clone() {
                        gas += gas_used(&provider, preconf_tx).await?;
                    }

                    reserve_with_calldata_bytes.push(to_ssz_bytes(&request.tip_transaction));
                    reserve_with_calldata_bytes.extend(request.preconf_tx.iter().map(to_ssz_bytes));
                }
                PreconfRequest::TypeB(preconf_req) => {
                    let tx = preconf_req
                        .transaction
                        .clone()
                        .expect("Empty transaction in list with calldata");
                    gas += gas_used(&provider, tx.clone()).await?;

                    let tx_bytes = to_ssz_bytes(&tx);
                    reserve_without_calldata_bytes.push(tx_bytes.clone());

                    let alloc_sig_sig =
                        signer.sign_hash(&keccak256(preconf_req.alloc_sig.as_bytes())).await?;

                    let raw_tx = hex_encode(&tx_bytes);
                    let signed = signer.sign_hash(&keccak256(raw_tx)).await?;
                    let request_sol =
                        to_solidity_type(preconf_req, alloc_sig_sig, tx_bytes, signed);

                    let get_tip_tx = taiyi_escrow
                        .getTip(request_sol)
                        .into_transaction_request()
                        .with_chain_id(chain_id)
                        .with_nonce(nonce)
                        .with_gas_limit(1_000_000)
                        .with_max_fee_per_gas(max_fee_per_gas)
                        .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
                        .build(&wallet)
                        .await?;
                    nonce += 1;
                    reserve_without_calldata_bytes.push(to_ssz_bytes(&get_tip_tx));
                }
            }

            amounts.push(U256::from(gas * base_fee));
        }

        let mut constraints = Vec::new();
        let sponsor_tx = taiyi_escrow
            .sponsorEthBatch(accounts, amounts)
            .into_transaction_request()
            .with_nonce(sponsor_nonce)
            .with_chain_id(chain_id)
            .with_gas_limit(1_000_000)
            .with_max_fee_per_gas(max_fee_per_gas)
            .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
            .build(&wallet)
            .await?;
        constraints.push(to_ssz_bytes(&sponsor_tx));

        let validators = get_validators(&constraints_url).await?;
        let fee_recipient = validators
            .iter()
            .filter_map(|validator| {
                if validator.slot == next_slot {
                    Some(validator.entry.message.fee_recipient)
                } else {
                    None
                }
            })
            .next()
            .expect("No validator available for next slot");
        let validator_payout_tx = TransactionRequest::default()
            .with_nonce(nonce)
            .with_chain_id(chain_id)
            .with_gas_limit(21_000)
            .with_max_fee_per_gas(max_fee_per_gas)
            .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
            .with_to(fee_recipient)
            .with_value(total_preconf_tips)
            .build(&wallet)
            .await?;
        reserve_without_calldata_bytes.push(to_ssz_bytes(&validator_payout_tx));

        info!("Found {} preconf requests for slot {} to be exhausted", pending.len(), next_slot);
        let mut exhaust_txs = Vec::new();
        for preconf_req in pending {
            let allog_sig_sig =
                signer.sign_hash(&keccak256(preconf_req.alloc_sig.as_bytes())).await?;
            let signed_empty = signer.sign_hash(&keccak256(Bytes::default())).await?;
            let request_sol =
                to_solidity_type(preconf_req, allog_sig_sig, Bytes::default(), signed_empty);

            let exhaust_tx = taiyi_escrow
                .exhaust(request_sol)
                .into_transaction_request()
                .with_chain_id(chain_id)
                .with_nonce(nonce)
                .with_gas_limit(1_000_000)
                .with_max_fee_per_gas(max_fee_per_gas)
                .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
                .build(&wallet)
                .await?;
            nonce += 1;

            exhaust_txs.push(to_ssz_bytes(&exhaust_tx));
        }

        constraints.extend(reserve_with_calldata_bytes);
        constraints.extend(reserve_without_calldata_bytes);
        constraints.extend(exhaust_txs);

        if constraints.is_empty() {
            return Ok(());
        }
        info!("Submitting {} constraints to relay for slot {}", constraints.len(), next_slot);
        let message = ConstraintsMessage {
            pubkey: bls_pubkey_to_alloy(&bls_signer.public_key()),
            slot: next_slot,
            top: false,
            transactions: constraints,
        };
        let digest = message.digest();
        let signature = bls_signature_to_alloy(&bls_signer.sign_hash(&digest).await);
        let signed_constraints_message = vec![SignedConstraints { message, signature }];

        let max_retries = 5;
        for i in 0..=max_retries {
            if let Err(e) =
                set_constraints(&constraints_url, signed_constraints_message.clone()).await
            {
                error!(err = ?e, "Error submitting constraints to relay, retrying...");
            }
            if i == max_retries {
                error!("Max retries reached while submitting to relay");
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if is_new_epoch {}
    }
    Ok(())
}

fn to_solidity_type(
    request: PreconfRequestTypeB,
    blockspace_allocation_sig_underwriter: Signature,
    raw_tx: Bytes,
    underwriter_signed_raw_tx: Signature,
) -> TaiyiEscrow::PreconfRequestBType {
    TaiyiEscrow::PreconfRequestBType {
        blockspaceAllocation: TaiyiEscrow::BlockspaceAllocation {
            gasLimit: U256::from(request.allocation.gas_limit),
            sender: request.signer(),
            recipient: request.allocation.recipient,
            deposit: request.allocation.deposit,
            tip: request.allocation.tip,
            targetSlot: U256::from(request.allocation.target_slot),
            blobCount: U256::from(request.allocation.blob_count),
        },
        blockspaceAllocationSignature: request.alloc_sig.as_bytes().into(),
        underwriterSignedBlockspaceAllocation: blockspace_allocation_sig_underwriter
            .as_bytes()
            .into(),
        rawTx: raw_tx,
        underwriterSignedRawTx: underwriter_signed_raw_tx.as_bytes().into(),
    }
}

pub async fn gas_used<P: Provider>(provider: &P, tx: TxEnvelope) -> eyre::Result<u64> {
    let trace_options = GethDebugTracingCallOptions::default();
    let trace = provider
        .debug_trace_call(tx.into(), BlockId::latest(), trace_options)
        .await?
        .try_into_default_frame()?;
    Ok(trace.gas)
}

fn to_ssz_bytes(tx: &TxEnvelope) -> Bytes {
    let mut tx_bytes = Vec::new();
    tx.encode_2718(&mut tx_bytes);
    Bytes::copy_from_slice(tx_bytes.as_ref())
}

async fn set_constraints(url: &str, constraints: Vec<SignedConstraints>) -> eyre::Result<()> {
    let url = format!("{url}/constraints/v1/builder/constraints");

    let response = Client::new().post(url.clone()).json(&constraints).send().await?;
    let status = response.status();

    let body = response.bytes().await?;
    let body = String::from_utf8_lossy(&body);

    if status.is_success() {
        debug!("Constraints submitted successfully");
    } else {
        error!("Failed to submit constraints {} {}", body, status);
    }

    Ok(())
}

pub async fn get_validators(url: &str) -> Result<Vec<Validator>, reqwest::Error> {
    let url = format!("{url}/relay/v1/builder/validators");
    let validators: Vec<Validator> = Client::new().get(url).send().await?.json().await?;
    Ok(validators)
}
