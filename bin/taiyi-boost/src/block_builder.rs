use std::sync::Arc;

use alloy_consensus::{Header, Transaction, TxEnvelope, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::{
    calc_excess_blob_gas, calc_next_block_base_fee,
    eip1559::BaseFeeParams,
    eip1898::BlockId,
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_network::primitives::BlockTransactionsKind;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_beacon::{constants::BLS_DST_SIG, BlsPublicKey};
use alloy_rpc_types_engine::JwtSecret;
use alloy_rpc_types_eth::Block;
use alloy_transport_http::{reqwest::Client, Http};
use beacon_api_client::{mainnet::Client as BeaconClient, BlockId as BLBlockId, StateId};
use cb_common::{
    pbs::{
        DenebSpec, ExecutionPayloadHeader, ExecutionPayloadHeaderMessage, KzgCommitments,
        PayloadAndBlobs, SignedExecutionPayloadHeader,
    },
    signer::BlsSecretKey,
};
use ethereum_consensus::deneb::{compute_domain, Context, DomainType, Root};
use eyre::Result;
use hex::FromHex;
use reqwest::Url;
use reth_primitives::{proofs, BlockBody, SealedBlock, SealedHeader, TransactionSigned};
use serde_json::Value;
use tracing::trace;
use tree_hash::TreeHash;

use crate::{
    engine::{EngineApiHint, EngineClient},
    types::{
        to_alloy_execution_payload, to_alloy_withdrawal, to_blobs_bundle, to_cb_execution_payload,
        to_cb_execution_payload_header, tx_envelope_to_signed,
    },
    utils::compute_signing_root,
};

#[derive(Debug, Clone)]
pub struct SignedPayloadResponse {
    pub header: SignedExecutionPayloadHeader,
    pub payload: PayloadAndBlobs,
}

// "Local built by Taiyi"
const DEFAULT_EXTRA_DATA: [u8; 20] = [
    0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x20, 0x62, 0x79, 0x20, 0x54,
    0x61, 0x69, 0x79, 0x69,
];

#[derive(Clone)]
pub struct LocalBlockBuilder {
    context: Context,
    beacon_api_client: BeaconClient,
    engine_api_client: EngineClient,
    execution_api_client: Arc<RootProvider<Http<Client>>>,
    fee_recipient: Address,
    extra_data: Bytes,
    bls_secret_key: BlsSecretKey,
}

impl LocalBlockBuilder {
    pub async fn new(
        context: Context,
        beacon_api: Url,
        engine_api: Url,
        execution_api: Url,
        jwt_secret: JwtSecret,
        fee_recipient: Address,
        bls_secret_key: BlsSecretKey,
    ) -> Self {
        let beacon_api_client = BeaconClient::new(beacon_api);
        let engine_api_client = EngineClient::new(engine_api, jwt_secret);
        let provider = ProviderBuilder::new().on_http(execution_api);
        Self {
            context,
            beacon_api_client,
            engine_api_client,
            execution_api_client: Arc::new(provider),
            fee_recipient,
            extra_data: DEFAULT_EXTRA_DATA.into(),
            bls_secret_key,
        }
    }

    /// The local block builder is modified from bolt's implementation.
    /// refer to: https://github.com/chainbound/bolt/blob/v0.3.0-alpha/bolt-sidecar/src/builder/payload_builder.rs#L112
    pub async fn build_local_payload(
        &self,
        target_slot: u64,
        transactions: &[TransactionSigned],
    ) -> Result<SealedBlock> {
        let latest_block = self
            .execution_api_client
            .get_block(BlockId::default(), BlockTransactionsKind::Full)
            .await?
            .expect("Failed to fetch latest block");
        let withdrawals = self.get_expected_withdrawals_at_head().await?;
        let prev_randao = self.get_prev_randao().await?;
        let parent_beacon_block_root = B256::from_slice(
            self.beacon_api_client.get_beacon_block_root(BLBlockId::Head).await?.as_slice(),
        );

        let versioned_hashes = transactions
            .iter()
            .flat_map(|tx| tx.blob_versioned_hashes())
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let base_fee_per_gas = calc_next_block_base_fee(
            latest_block.header.gas_used,
            latest_block.header.gas_limit,
            latest_block.header.base_fee_per_gas.unwrap_or_default(),
            BaseFeeParams::ethereum(),
        );
        let excess_blob_gas = calc_excess_blob_gas(
            latest_block.header.excess_blob_gas.unwrap_or_default(),
            latest_block.header.blob_gas_used.unwrap_or_default(),
        );

        let blob_gas_used =
            transactions.iter().fold(0, |acc, tx| acc + tx.blob_gas_used().unwrap_or_default());
        let genesis_time = match self.context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.context.min_genesis_time + self.context.genesis_delay,
        };
        let block_timestamp = genesis_time + (target_slot * self.context.seconds_per_slot);
        let block_body = BlockBody {
            ommers: Vec::new(),
            transactions: transactions.to_vec(),
            withdrawals: Some(Withdrawals::new(withdrawals.clone())),
        };

        let ctx = BlockContext {
            base_fee_per_gas,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
            prev_randao,
            extra_data: self.extra_data.clone(),
            fee_recipient: self.fee_recipient,
            transactions_root: proofs::calculate_transaction_root(transactions),
            withdrawals_root: proofs::calculate_withdrawals_root(&withdrawals),
            block_timestamp,
        };

        let mut hints = Hints::default();
        let max_iterations = 20;
        let mut i = 0;
        loop {
            let header = build_header_with_hints_and_context(&latest_block, &hints, &ctx);

            let sealed_hash = header.hash_slow();
            let sealed_header = SealedHeader::new(header, sealed_hash);
            let sealed_block = SealedBlock::new(sealed_header, block_body.clone());

            let block_hash = hints.block_hash.unwrap_or(sealed_block.hash());

            let exec_payload = to_alloy_execution_payload(&sealed_block, block_hash);

            let engine_hint = self
                .engine_api_client
                .fetch_next_payload_hint(&exec_payload, &versioned_hashes, parent_beacon_block_root)
                .await?;

            match engine_hint {
                EngineApiHint::BlockHash(hash) => {
                    trace!("Should not receive block hash hint {:?}", hash);
                    hints.block_hash = Some(hash)
                }

                EngineApiHint::GasUsed(gas) => {
                    hints.gas_used = Some(gas);
                    hints.block_hash = None;
                }
                EngineApiHint::StateRoot(hash) => {
                    hints.state_root = Some(hash);
                    hints.block_hash = None
                }
                EngineApiHint::ReceiptsRoot(hash) => {
                    hints.receipts_root = Some(hash);
                    hints.block_hash = None
                }
                EngineApiHint::LogsBloom(bloom) => {
                    hints.logs_bloom = Some(bloom);
                    hints.block_hash = None
                }

                EngineApiHint::ValidPayload => return Ok(sealed_block),
            }

            if i > max_iterations {
                return Err(eyre::eyre!(
                    "Too many iterations: Failed to fetch all missing header values from geth error messages",
                ));
            }

            i += 1;
        }
    }

    /// Fetch the expected withdrawals for the given slot from the beacon chain.
    async fn get_expected_withdrawals_at_head(&self) -> Result<Vec<Withdrawal>> {
        Ok(self
            .beacon_api_client
            .get_expected_withdrawals(StateId::Head, None)
            .await?
            .into_iter()
            .map(to_alloy_withdrawal)
            .collect::<Vec<_>>())
    }

    pub async fn build_signed_payload_response(
        &self,
        target_slot: u64,
        transactions: &[TxEnvelope],
    ) -> Result<SignedPayloadResponse> {
        let signed_transactions: Vec<TransactionSigned> =
            transactions.iter().map(|tx| tx_envelope_to_signed(tx.clone())).collect();
        let blobs_bundle = to_blobs_bundle(transactions);
        let kzg_commitments = blobs_bundle.clone().unwrap_or_default().commitments.clone();
        let block = self.build_local_payload(target_slot, &signed_transactions).await?;
        let value = U256::from(100_000_000_000_000_000_000u128);
        let execution_payload = to_cb_execution_payload(&block);
        let payload_and_blobs = PayloadAndBlobs { execution_payload, blobs_bundle };
        let execution_payload_header = to_cb_execution_payload_header(&block);

        let signed_bid = self.create_signed_execution_payload_header(
            value,
            execution_payload_header,
            kzg_commitments,
        )?;

        Ok(SignedPayloadResponse { header: signed_bid, payload: payload_and_blobs })
    }

    pub fn create_signed_execution_payload_header(
        &self,
        value: U256,
        header: ExecutionPayloadHeader<DenebSpec>,
        blob_kzg_commitments: KzgCommitments<DenebSpec>,
    ) -> Result<SignedExecutionPayloadHeader> {
        let consensus_pubkey = self.bls_secret_key.sk_to_pk().to_bytes();
        let pubkey = BlsPublicKey::from(consensus_pubkey);
        let message = ExecutionPayloadHeaderMessage { header, blob_kzg_commitments, value, pubkey };
        // Note: the application builder domain specs require the genesis_validators_root
        // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
        // same rule.
        let root = Root::default();
        let domain = compute_domain(
            DomainType::ApplicationBuilder,
            Some(self.context.genesis_fork_version),
            Some(root),
            &self.context,
        )
        .expect("Failed to compute domain");
        let object_root = message.tree_hash_root().0;
        let signing_root = compute_signing_root(object_root, domain);
        let signature = self.bls_secret_key.sign(&signing_root, BLS_DST_SIG, &[]).to_bytes();
        Ok(SignedExecutionPayloadHeader { message, signature: signature.into() })
    }

    /// Fetch the previous RANDAO value from the beacon chain.
    ///
    /// NOTE: for some reason, using the ApiResult from `beacon_api_client` doesn't work, so
    /// we are making a direct request to the beacon client endpoint.
    async fn get_prev_randao(&self) -> Result<B256> {
        let url = self.beacon_api_client.endpoint.join("/eth/v1/beacon/states/head/randao")?;

        reqwest::Client::new()
            .get(url)
            .send()
            .await?
            .json::<Value>()
            .await?
            .pointer("/data/randao")
            .and_then(|value| value.as_str())
            .map(|value| B256::from_hex(value).map_err(|e| eyre::eyre!("{:?}", e)))
            .ok_or_else(|| eyre::eyre!("Failed to fetch prev RANDAO"))?
    }
}

/// Build a header with the given hints and context values.
fn build_header_with_hints_and_context(
    latest_block: &Block,
    hints: &Hints,
    context: &BlockContext,
) -> Header {
    // Use the available hints, or default to an empty value if not present.
    let gas_used = hints.gas_used.unwrap_or_default();
    let receipts_root = hints.receipts_root.unwrap_or_default();
    let logs_bloom = hints.logs_bloom.unwrap_or_default();
    let state_root = hints.state_root.unwrap_or_default();

    Header {
        parent_hash: latest_block.header.hash,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: context.fee_recipient,
        state_root,
        transactions_root: context.transactions_root,
        receipts_root,
        withdrawals_root: Some(context.withdrawals_root),
        logs_bloom,
        difficulty: U256::ZERO,
        number: latest_block.header.number + 1,
        gas_limit: latest_block.header.gas_limit,
        gas_used,
        timestamp: context.block_timestamp,
        mix_hash: context.prev_randao,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(context.base_fee_per_gas),
        blob_gas_used: Some(context.blob_gas_used),
        excess_blob_gas: Some(context.excess_blob_gas),
        parent_beacon_block_root: Some(context.parent_beacon_block_root),
        requests_hash: None,
        extra_data: context.extra_data.clone(),
    }
}

/// Lightweight context struct to hold the necessary values for
/// building a sealed block. Some of this data is fetched from the
/// beacon chain, while others are calculated locally or from the
/// transactions themselves.
#[derive(Debug, Default)]
struct BlockContext {
    extra_data: Bytes,
    base_fee_per_gas: u64,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    prev_randao: B256,
    fee_recipient: Address,
    transactions_root: B256,
    withdrawals_root: B256,
    parent_beacon_block_root: B256,
    block_timestamp: u64,
}

#[derive(Debug, Default)]
struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub state_root: Option<B256>,
    pub block_hash: Option<B256>,
}

#[cfg(test)]
mod test {
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;
    use crate::utils::{
        get_now_timestamp,
        tests::{gen_test_tx_request, get_test_config},
    };

    #[test]
    fn local_extra_data() {
        use super::DEFAULT_EXTRA_DATA;
        let extra_data = "Local built by Taiyi";
        let extra_data_bytes = extra_data.as_bytes();
        assert_eq!(extra_data_bytes.len(), 20);
        assert_eq!(extra_data_bytes, DEFAULT_EXTRA_DATA);
        // 0x4c6f63616c206275696c74206279205461697969
        // println!("Local extra data: 0x{}", hex::encode(extra_data_bytes));
    }

    #[tokio::test]
    #[ignore = "This test needs env configs to connect to real rpcs"]
    async fn test_build_local_payload() -> eyre::Result<()> {
        let config = get_test_config()?;
        let raw_sk = std::env::var("PRIVATE_KEY")?;
        let hex_sk = raw_sk.strip_prefix("0x").unwrap_or(&raw_sk);

        let context: Context = config.network.try_into()?;
        let chain_id = context.deposit_chain_id as u64;

        let local_builder = LocalBlockBuilder::new(
            context.clone(),
            config.beacon_api,
            config.engine_api,
            config.execution_api.clone(),
            config.engine_jwt.0,
            config.fee_recipient,
            config.builder_private_key.0,
        )
        .await;

        let sk = SigningKey::from_slice(hex::decode(hex_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);
        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_http(config.execution_api);
        let sender = Address::from_private_key(&sk);
        let nonce = provider.get_transaction_count(sender).await?;

        let tx = gen_test_tx_request(sender, chain_id, Some(nonce));
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = TransactionSigned::decode_2718(&mut raw_encoded.as_slice())?;

        let genesis_time = match context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => context.min_genesis_time + context.genesis_delay,
        };

        let slot = genesis_time + (get_now_timestamp().unwrap() / context.seconds_per_slot) + 1;

        let block = local_builder.build_local_payload(slot, &[tx_signed_reth]).await?;
        assert_eq!(block.body.transactions.len(), 1);
        Ok(())
    }
}
