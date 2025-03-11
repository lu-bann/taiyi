// the code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/builder/fallback/engine_hinter.rs
use std::ops::Deref;

use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_provider::ext::EngineApi;
use alloy_rpc_types_engine::{ClientCode, ExecutionPayloadV3, JwtSecret, PayloadStatusEnum};
use alloy_rpc_types_eth::{Block, Withdrawal, Withdrawals};
use engine_hints::parse_hint_from_engine_response;
use reqwest::Url;
use reth_primitives::{
    BlockBody, Header as RethHeader, SealedBlock, SealedHeader, TransactionSigned,
};
use tracing::{debug, error};

use crate::{engine::EngineClient, error::BuilderError, types::to_alloy_execution_payload};

mod engine_hints;

/// The [EngineHinter] is responsible for gathering "hints" from the
/// engine API error responses to complete the sealed block.
///
/// Since error messages are not overly standardized across execution clients,
/// we need to know which execution client is being used to properly parse the hints.
///
/// This can be done by querying the EL `engine_getClientVersionV1` method.
#[derive(Debug, Clone)]
pub struct EngineHinter {
    engine_client: EngineClient,
}

impl Deref for EngineHinter {
    type Target = EngineClient;

    fn deref(&self) -> &Self::Target {
        &self.engine_client
    }
}

impl EngineHinter {
    /// Create a new [EngineHinter] instance with the given JWT and engine RPC URL.
    pub fn new(jwt_secret: JwtSecret, engine_rpc_url: Url) -> Self {
        Self { engine_client: EngineClient::new_http(engine_rpc_url, jwt_secret) }
    }

    /// Collect hints from the engine API to complete the sealed block.
    /// This method will keep fetching hints until the payload is valid.
    pub async fn fetch_payload_from_hints(
        &self,
        mut ctx: EngineHinterContext,
    ) -> Result<SealedBlock, BuilderError> {
        // The block body can be the same for all iterations, since it only contains
        // the transactions and withdrawals from the context.
        let body = ctx.build_block_body();

        // Loop until we get a valid payload from the engine API. On each iteration,
        // we build a new block header with the hints from the context and fetch the next hint.
        let max_iterations = 20;
        let mut iteration = 0;
        loop {
            debug!(%iteration, "Fetching hint from engine API");

            // Build a new block header using the hints from the context
            let header = ctx.build_block_header_with_hints();

            let sealed_hash = header.hash_slow();
            let sealed_header = SealedHeader::new(header, sealed_hash);
            let sealed_block = SealedBlock::new(sealed_header, body.clone());
            let block_hash = ctx.hints.block_hash.unwrap_or(sealed_block.hash());

            // build the new execution payload from the block header
            let exec_payload = to_alloy_execution_payload(&sealed_block, block_hash);

            // attempt to fetch the next hint from the engine API payload response
            let hint = self.next_hint(exec_payload, &ctx).await?;

            if matches!(hint, EngineApiHint::ValidPayload) {
                return Ok(sealed_block);
            }

            // Populate the new hint in the context and continue the loop
            ctx.hints.populate_new(hint);

            iteration += 1;
            if iteration >= max_iterations {
                return Err(BuilderError::ExceededMaxHintIterations(max_iterations));
            }
        }
    }

    /// Yield the next hint from the engine API by calling `engine_newPayloadV3`
    /// and parsing the response to extract the hint.
    ///
    /// Returns Ok([EngineApiHint::ValidPayload]) if the payload is valid.
    async fn next_hint(
        &self,
        exec_payload: ExecutionPayloadV3,
        ctx: &EngineHinterContext,
    ) -> Result<EngineApiHint, BuilderError> {
        let payload_status = self
            .engine_client
            .new_payload_v3(
                exec_payload,
                ctx.blob_versioned_hashes.clone(),
                ctx.parent_beacon_block_root,
            )
            .await?;

        let validation_error = match payload_status.status {
            PayloadStatusEnum::Valid => return Ok(EngineApiHint::ValidPayload),
            PayloadStatusEnum::Invalid { validation_error } => validation_error,
            PayloadStatusEnum::Syncing | PayloadStatusEnum::Accepted => {
                error!(status = ?payload_status.status, "Unexpected payload status from engine API");
                return Err(BuilderError::UnexpectedPayloadStatus(payload_status.status));
            }
        };

        // Parse the hint from the engine API response, based on the EL client code
        let hint = match parse_hint_from_engine_response(ctx.el_client_code, &validation_error) {
            Ok(Some(hint)) => hint,
            Ok(None) => {
                let el_name = ctx.el_client_code.client_name().to_string();
                return Err(BuilderError::FailedToParseHintsFromEngine(el_name));
            }
            Err(e) => return Err(e),
        };

        Ok(hint)
    }
}

/// Engine API hint values that can be fetched from the engine API
/// to complete the sealed block. These hints are used to fill in
/// missing values in the block header.
#[derive(Debug, Copy, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EngineApiHint {
    BlockHash(B256),
    GasUsed(u64),
    StateRoot(B256),
    ReceiptsRoot(B256),
    LogsBloom(Bloom),
    ValidPayload,
}

/// The collection of hints that can be fetched from the engine API
/// via the [EngineHinter] to complete the sealed block.
///
/// When a field is `None`, we set it to its default value in the [ExecutionPayload]
/// and try to get the hint from the engine API response to fill its value.
#[derive(Debug, Default)]
pub struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub state_root: Option<B256>,
    pub block_hash: Option<B256>,
}

impl Hints {
    /// Populate the new hint value in the context.
    pub fn populate_new(&mut self, hint: EngineApiHint) {
        match hint {
            EngineApiHint::ValidPayload => { /* No-op */ }

            // If we receive a block hash hint, set it and keep it for the next one.
            // This should not happen, but in case it does, it doesn't break the flow.
            EngineApiHint::BlockHash(hash) => self.block_hash = Some(hash),

            // For regular hint types, set the value and reset the block hash
            EngineApiHint::GasUsed(gas) => {
                self.gas_used = Some(gas);
                self.block_hash = None;
            }
            EngineApiHint::StateRoot(hash) => {
                self.state_root = Some(hash);
                self.block_hash = None;
            }
            EngineApiHint::ReceiptsRoot(hash) => {
                self.receipts_root = Some(hash);
                self.block_hash = None;
            }
            EngineApiHint::LogsBloom(bloom) => {
                self.logs_bloom = Some(bloom);
                self.block_hash = None;
            }
        }
    }
}

/// Context holding the necessary values for
/// building a sealed block. Some of this data is fetched from the
/// beacon chain, while others are calculated locally or from the
/// transactions themselves.
#[derive(Debug)]
pub struct EngineHinterContext {
    pub extra_data: Bytes,
    pub base_fee: u64,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    pub prev_randao: B256,
    pub fee_recipient: Address,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    pub parent_beacon_block_root: B256,
    pub blob_versioned_hashes: Vec<B256>,
    pub block_timestamp: u64,
    pub transactions: Vec<TransactionSigned>,
    pub withdrawals: Vec<Withdrawal>,
    pub head_block: Block,
    pub hints: Hints,
    pub el_client_code: ClientCode,
}

impl EngineHinterContext {
    /// Build a block body using the transactions and withdrawals from the context.
    pub fn build_block_body(&self) -> BlockBody {
        BlockBody {
            ommers: Vec::new(),
            transactions: self.transactions.clone(),
            withdrawals: Some(Withdrawals::new(self.withdrawals.clone())),
        }
    }

    /// Build a header using the info from the context.
    /// Use any hints available, and default to an empty value if not present.
    pub fn build_block_header_with_hints(&self) -> RethHeader {
        // Use the available hints, or default to an empty value if not present.
        let gas_used = self.hints.gas_used.unwrap_or_default();
        let receipts_root = self.hints.receipts_root.unwrap_or_default();
        let logs_bloom = self.hints.logs_bloom.unwrap_or_default();
        let state_root = self.hints.state_root.unwrap_or_default();

        RethHeader {
            parent_hash: self.head_block.header.hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: self.fee_recipient,
            state_root,
            transactions_root: self.transactions_root,
            receipts_root,
            withdrawals_root: Some(self.withdrawals_root),
            logs_bloom,
            difficulty: U256::ZERO,
            number: self.head_block.header.number + 1,
            gas_limit: self.head_block.header.gas_limit,
            gas_used,
            timestamp: self.block_timestamp,
            mix_hash: self.prev_randao,
            nonce: B64::ZERO,
            base_fee_per_gas: Some(self.base_fee),
            blob_gas_used: Some(self.blob_gas_used),
            excess_blob_gas: Some(self.excess_blob_gas),
            parent_beacon_block_root: Some(self.parent_beacon_block_root),
            extra_data: self.extra_data.clone(),
            // TODO: handle the Pectra-related fields
            requests_hash: None,
            target_blobs_per_block: None,
        }
    }
}
