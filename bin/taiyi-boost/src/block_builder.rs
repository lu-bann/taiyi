// The code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/builder/fallback/payload_builder.rs
use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::{calc_excess_blob_gas, calc_next_block_base_fee, eip1559::BaseFeeParams};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types_beacon::{constants::BLS_DST_SIG, BlsPublicKey};
use alloy_rpc_types_engine::JwtSecret;
use cb_common::{
    pbs::{
        ElectraSpec, ExecutionPayloadHeader, ExecutionPayloadHeaderMessageElectra,
        ExecutionRequests, GetHeaderResponse, KzgCommitments, PayloadAndBlobsElectra,
        SignedExecutionPayloadHeader,
    },
    signer::BlsSecretKey,
};
use ethereum_consensus::deneb::{compute_domain, Context, DomainType, Root};
use reqwest::Url;
use reth_primitives::{proofs, SealedBlock, TransactionSigned};
use taiyi_beacon_client::BeaconClient;
use tracing::debug;
use tree_hash::TreeHash;

use crate::{
    engine_hinter::{EngineHinter, EngineHinterContext},
    error::BuilderError,
    execution::ExecutionClient,
    types::{
        to_blobs_bundle, to_cb_execution_payload, to_cb_execution_payload_header,
        tx_envelope_to_signed,
    },
    utils::compute_signing_root,
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
    context: Context,
    beacon_api_client: BeaconClient,
    engine_hinter: EngineHinter,
    execution_api_client: ExecutionClient,
    fee_recipient: Address,
    extra_data: Bytes,
    bls_secret_key: BlsSecretKey,
}

// The local block builder was based on bolt's implementation.
// See: https://github.com/chainbound/bolt/blob/v0.3.0-alpha/bolt-sidecar/src/builder/payload_builder.rs
impl LocalBlockBuilder {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        context: Context,
        beacon_api: Url,
        engine_api: Url,
        execution_api: Url,
        jwt_secret: JwtSecret,
        fee_recipient: Address,
        bls_secret_key: BlsSecretKey,
        auth_token: Option<String>,
    ) -> Self {
        let beacon_api_client = BeaconClient::new(beacon_api, auth_token);
        let engine_hinter = EngineHinter::new(jwt_secret, engine_api);
        let execution_api_client = ExecutionClient::new(execution_api);
        Self {
            context,
            beacon_api_client,
            engine_hinter,
            execution_api_client,
            fee_recipient,
            extra_data: DEFAULT_EXTRA_DATA.into(),
            bls_secret_key,
        }
    }

    /// Build a local payload for the given target slot and transactions in case relays fail to
    /// provide a payload that meets the commitment requirements.
    pub async fn build_local_payload(
        &self,
        target_slot: u64,
        transactions: &[TransactionSigned],
    ) -> Result<SealedBlock, BuilderError> {
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
        let genesis_time = match self.context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.context.min_genesis_time + self.context.genesis_delay,
        };
        let block_timestamp = genesis_time + (target_slot * self.context.seconds_per_slot);

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
        transactions: &[TxEnvelope],
    ) -> eyre::Result<SignedPayloadResponse> {
        let signed_transactions: Vec<TransactionSigned> =
            transactions.iter().map(|tx| tx_envelope_to_signed(tx.clone())).collect();
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
            execution_requests: ExecutionRequests::default(),
        };
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
}

#[cfg(test)]
mod test {
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_primitives::Address;
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;
    use cb_common::utils::utcnow_sec;

    use super::*;
    use crate::utils::tests::{gen_test_tx_request, get_test_config};

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
    async fn test_build_local_payload() -> eyre::Result<()> {
        let Some(config) = get_test_config()? else {
            eprintln!("Skipping test because required environment variables are not set");
            return Ok(());
        };
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
            None,
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

        let slot = (utcnow_sec() - genesis_time) / context.seconds_per_slot + 1;

        let block = local_builder.build_local_payload(slot, &[tx_signed_reth]).await?;
        assert_eq!(block.body.transactions.len(), 1);
        Ok(())
    }
}
