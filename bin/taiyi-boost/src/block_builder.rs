// The code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/builder/fallback/payload_builder.rs
use alloy::consensus::{proofs, Block, Header, Sealed, Transaction, TxEnvelope};
use alloy::eips::{calc_next_block_base_fee, eip1559::BaseFeeParams};
use alloy::primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsPublicKey};
use alloy_rpc_types_engine::JwtSecret;
use cb_common::{
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        ElectraSpec, ExecutionPayloadHeader, ExecutionPayloadHeaderMessageElectra,
        ExecutionRequests, GetHeaderResponse, KzgCommitments, PayloadAndBlobsElectra,
        SignedExecutionPayloadHeader,
    },
};
use reqwest::Url;
use taiyi_beacon_client::BeaconClient;
use taiyi_cmd::keys_management::signing::{compute_fork_data_root, compute_signing_root};
use taiyi_crypto::bls::SecretKey as BlsSecretKey;
use tracing::debug;
use tree_hash::TreeHash;

use crate::{
    engine_hinter::{EngineHinter, EngineHinterContext},
    error::BuilderError,
    execution::ExecutionClient,
    types::{to_blobs_bundle, to_cb_execution_payload, to_cb_execution_payload_header},
};

#[derive(Debug, Clone)]
pub struct SignedPayloadResponse {
    pub header: GetHeaderResponse,
    pub payload: PayloadAndBlobsElectra,
}

// "Local built by Taiyi"
const DEFAULT_EXTRA_DATA: [u8; 20] = [
    0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x20, 0x62, 0x79, 0x20, 0x54,
    0x61, 0x69, 0x79, 0x69,
];

#[derive(Clone)]
pub struct LocalBlockBuilder {
    genesis_time: u64,
    seconds_per_slot: u64,
    beacon_api_client: BeaconClient,
    engine_hinter: EngineHinter,
    execution_api_client: ExecutionClient,
    fee_recipient: Address,
    extra_data: Bytes,
    bls_secret_key: BlsSecretKey,
    fork_version: [u8; 4],
}

fn calc_excess_blob_gas(excess_blob_gas: u64, blob_gas_used: u64, max_blob_gas: u64) -> u64 {
    let blob_gas_info = excess_blob_gas.saturating_add(blob_gas_used);
    blob_gas_info - std::cmp::min(blob_gas_info, max_blob_gas)
}

const TARGET_BLOB_GAS_PER_BLOCK: u64 = 786432;

// The local block builder was based on bolt's implementation.
// See: https://github.com/chainbound/bolt/blob/v0.3.0-alpha/bolt-sidecar/src/builder/payload_builder.rs
impl LocalBlockBuilder {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        genesis_time: u64,
        seconds_per_slot: u64,
        beacon_api: Url,
        engine_api: Url,
        execution_api: Url,
        jwt_secret: JwtSecret,
        fee_recipient: Address,
        bls_secret_key: BlsSecretKey,
        auth_token: Option<String>,
        fork_version: [u8; 4],
    ) -> Self {
        let beacon_api_client = BeaconClient::new(beacon_api.to_string(), auth_token);
        let engine_hinter = EngineHinter::new(jwt_secret, engine_api);
        let execution_api_client = ExecutionClient::new(execution_api);
        Self {
            genesis_time,
            seconds_per_slot,
            beacon_api_client,
            engine_hinter,
            execution_api_client,
            fee_recipient,
            extra_data: DEFAULT_EXTRA_DATA.into(),
            bls_secret_key,
            fork_version,
        }
    }

    /// Build a local payload for the given target slot and transactions in case relays fail to
    /// provide a payload that meets the commitment requirements.
    pub async fn build_local_payload(
        &self,
        target_slot: u64,
        transactions: &[TxEnvelope],
    ) -> Result<Block<TxEnvelope, Sealed<Header>>, BuilderError> {
        // Fetch the latest block to get the necessary parent values for the new block.
        // For the timestamp, we must use the one expected by the beacon chain instead, to
        // prevent edge cases where the proposer before us has missed their slot and therefore
        // the timestamp of the previous block is too far in the past.
        let head_block_fut = self.execution_api_client.get_block(None, true);

        // Fetch the execution client info from the engine API in order to know what hint
        // types the engine hinter can parse from the engine API responses.
        let el_client_info_fut = self.engine_hinter.engine_client_version();

        let (head_block, el_client_info) = tokio::try_join!(head_block_fut, el_client_info_fut)?;

        let el_client_code = el_client_info.first().ok_or(BuilderError::MissingClientInfo)?.code;
        debug!(client = %el_client_code.client_name(), "Fetched execution client info");

        // Fetch required head info from the beacon client
        let parent_beacon_block_root_fut = self.beacon_api_client.get_parent_beacon_block_root();
        let withdrawals_fut = self.beacon_api_client.get_expected_withdrawals_at_head();
        let prev_randao_fut = self.beacon_api_client.get_prev_randao();

        let (parent_beacon_block_root, withdrawals, prev_randao) =
            tokio::try_join!(parent_beacon_block_root_fut, withdrawals_fut, prev_randao_fut)?;

        // The next block timestamp must be calculated manually rather than relying on the
        // previous execution block, to cover the edge case where any previous slots have
        // been missed by the proposers immediately before us.
        let block_timestamp = self.genesis_time + (target_slot * self.seconds_per_slot);

        let blob_versioned_hashes = transactions
            .iter()
            .flat_map(|tx| tx.blob_versioned_hashes())
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        let base_fee = calc_next_block_base_fee(
            head_block.header.gas_used,
            head_block.header.gas_limit,
            head_block.header.base_fee_per_gas.unwrap_or_default(),
            BaseFeeParams::ethereum(),
        );

        let excess_blob_gas = calc_excess_blob_gas(
            head_block.header.excess_blob_gas.unwrap_or_default(),
            head_block.header.blob_gas_used.unwrap_or_default(),
            TARGET_BLOB_GAS_PER_BLOCK,
        );

        let blob_gas_used =
            transactions.iter().fold(0, |acc, tx| acc + tx.blob_gas_used().unwrap_or_default());

        let ctx = EngineHinterContext {
            base_fee,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
            prev_randao,
            extra_data: self.extra_data.clone(),
            fee_recipient: self.fee_recipient,
            transactions_root: proofs::calculate_transaction_root(transactions),
            withdrawals_root: proofs::calculate_withdrawals_root(&withdrawals),
            transactions: transactions.to_vec(),
            blob_versioned_hashes,
            block_timestamp,
            withdrawals: withdrawals.to_vec(),
            head_block,
            el_client_code,
            // start the context with empty hints
            hints: Default::default(),
        };

        // Use the engine API to fetch the missing value for the payload, until we have
        // all the necessary data to consider it valid and seal the block.
        self.engine_hinter.fetch_payload_from_hints(ctx).await
    }

    pub async fn build_signed_payload_response(
        &self,
        target_slot: u64,
        signed_transactions: Vec<TxEnvelope>,
    ) -> eyre::Result<SignedPayloadResponse> {
        let transactions: &[TxEnvelope] = signed_transactions.as_ref();
        let blobs_bundle = to_blobs_bundle(transactions);
        let kzg_commitments = blobs_bundle.clone().commitments.clone();
        let block = self.build_local_payload(target_slot, &signed_transactions).await?;
        let value = U256::from(100_000_000_000_000_000_000u128);
        let execution_payload = to_cb_execution_payload(&block);
        let payload_and_blobs = PayloadAndBlobsElectra { execution_payload, blobs_bundle };
        let execution_payload_header = to_cb_execution_payload_header(&block);

        let signed_bid = self.create_signed_execution_payload_header(
            value,
            execution_payload_header,
            kzg_commitments,
        )?;

        Ok(SignedPayloadResponse {
            header: cb_common::pbs::VersionedResponse::Electra(signed_bid),
            payload: payload_and_blobs,
        })
    }

    pub fn create_signed_execution_payload_header(
        &self,
        value: U256,
        header: ExecutionPayloadHeader<ElectraSpec>,
        blob_kzg_commitments: KzgCommitments<ElectraSpec>,
    ) -> eyre::Result<SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>> {
        let consensus_pubkey = self.bls_secret_key.sk_to_pk().to_bytes();
        let pubkey = BlsPublicKey::from(consensus_pubkey);
        let message = ExecutionPayloadHeaderMessageElectra {
            header,
            blob_kzg_commitments,
            value,
            pubkey,
            execution_requests: <ExecutionRequests<ElectraSpec>>::default(),
        };
        // Note: the application builder domain specs require the genesis_validators_root
        // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
        // same rule.
        let domain = compute_domain(self.fork_version)?;
        let object_root = message.tree_hash_root().0;
        let signing_root = compute_signing_root(object_root, domain.0)?;
        let signature =
            self.bls_secret_key.sign(signing_root.as_slice(), BLS_DST_SIG, &[]).to_bytes();
        Ok(SignedExecutionPayloadHeader { message, signature: signature.into() })
    }
}

fn compute_domain(fork_version: [u8; 4]) -> eyre::Result<FixedBytes<32>> {
    let genesis_validators_root = B256::ZERO;
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

    let mut domain = FixedBytes::<32>::default();
    domain[..4].copy_from_slice(&APPLICATION_BUILDER_DOMAIN);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use crate::ExtraConfig;
    use alloy::eips::eip2718::{Decodable2718, Encodable2718};
    use alloy::network::{EthereumWallet, TransactionBuilder};
    use alloy::primitives::{address, Address};
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::signers::k256::ecdsa::SigningKey;
    use alloy::signers::local::PrivateKeySigner;
    use cb_common::utils::utcnow_sec;
    use std::env;
    use taiyi_beacon_client::{BlsSecretKeyWrapper, JwtSecretWrapper};

    use super::*;
    use crate::constraints::tests::gen_test_tx_request;

    fn get_test_config() -> eyre::Result<Option<ExtraConfig>> {
        if env::var("ENGINE_API").is_err()
            || env::var("EXECUTION_API").is_err()
            || env::var("BEACON_API").is_err()
            || env::var("JWT_SECRET").is_err()
            || env::var("NETWORK").is_err()
        {
            return Ok(None);
        }

        let engine_api = env::var("ENGINE_API").unwrap();
        let execution_api = env::var("EXECUTION_API").unwrap();
        let beacon_api = env::var("BEACON_API").unwrap();
        let jwt_secret = env::var("JWT_SECRET").unwrap();
        let auth_token = env::var("AUTH_TOKEN").ok();

        Ok(Some(ExtraConfig {
            engine_api: Url::parse(&engine_api)?,
            execution_api: Url::parse(&execution_api)?,
            beacon_api: Url::parse(&beacon_api)?,
            fee_recipient: address!("dd5DFB73a16B21a6D6bAfF278Fe05D97f71ACfD3"),
            builder_private_key: BlsSecretKeyWrapper::from(
                "0x6b845831c99c6bf43364bee624447d39698465df5c07f2cc4dca6e0acfbe46cd",
            ),
            engine_jwt: JwtSecretWrapper::try_from(jwt_secret.as_str())?,
            auth_token,
        }))
    }

    #[test]
    fn local_extra_data() {
        use super::DEFAULT_EXTRA_DATA;
        let extra_data = "Local built by Taiyi";
        let extra_data_bytes = extra_data.as_bytes();
        assert_eq!(extra_data_bytes.len(), 20);
        assert_eq!(extra_data_bytes, DEFAULT_EXTRA_DATA);
    }

    #[tokio::test]
    async fn test_build_local_payload() -> eyre::Result<()> {
        let Some(config) = get_test_config()? else {
            eprintln!("Skipping test because required environment variables are not set");
            return Ok(());
        };
        let raw_sk = std::env::var("PRIVATE_KEY")?;
        let hex_sk = raw_sk.strip_prefix("0x").unwrap_or(&raw_sk);

        let chain_id: u64 = 13;
        let genesis_time: u64 = 1;
        let seconds_per_slot: u64 = 10;
        let fork_version = [0u8; 4];

        let local_builder = LocalBlockBuilder::new(
            genesis_time,
            seconds_per_slot,
            config.beacon_api,
            config.engine_api,
            config.execution_api.clone(),
            config.engine_jwt.0,
            config.fee_recipient,
            config.builder_private_key.0,
            None,
            fork_version,
        )
        .await;

        let sk = SigningKey::from_slice(hex::decode(hex_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new().connect_http(config.execution_api);
        let sender = Address::from_private_key(&sk);
        let nonce = provider.get_transaction_count(sender).await?;

        let tx = gen_test_tx_request(sender, chain_id, Some(nonce));
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = TxEnvelope::decode_2718(&mut raw_encoded.as_slice())?;

        let slot = (utcnow_sec() - genesis_time) / seconds_per_slot + 1;

        let block = local_builder.build_local_payload(slot, &[tx_signed_reth]).await?;
        assert_eq!(block.body.transactions.len(), 1);
        Ok(())
    }

    #[test]
    fn if_parent_gas_used_plus_parent_excess_gas_is_below_upper_bound_then_calc_excess_blob_gas_returns_zero(
    ) {
        let parent_excess_gas = 100u64;
        let parent_gas_used = 50u64;
        let max_gas = 200u64;
        let excess_gas = calc_excess_blob_gas(parent_excess_gas, parent_gas_used, max_gas);
        assert_eq!(excess_gas, 0u64);
    }

    #[test]
    fn if_parent_gas_used_plus_parent_excess_gas_is_above_upper_bound_then_calc_excess_blob_gas_returns_difference(
    ) {
        let parent_excess_gas = 100u64;
        let parent_gas_used = 150u64;
        let max_gas = 200u64;
        let excess_gas = calc_excess_blob_gas(parent_excess_gas, parent_gas_used, max_gas);
        assert_eq!(excess_gas, 50u64);
    }
}
