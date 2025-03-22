use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// Helper struct to compute the signing root for a given object
/// root and signing domain as defined in the Ethereum 2.0 specification.
#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

/// Compute the signing root for a given object root and signing domain.
pub fn compute_signing_root(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root().0
}

#[cfg(test)]
pub(crate) mod tests {
    use std::env;

    use alloy_network::TransactionBuilder;
    use alloy_primitives::{address, Address, Bytes, B256, U256};
    use alloy_rpc_types_eth::TransactionRequest;
    use eyre::Result;
    use lighthouse_types::{ExecPayload, MainnetEthSpec, SignedBeaconBlockDeneb};
    use reqwest::Url;
    use ssz::Decode;

    use crate::{
        types::{BlsSecretKeyWrapper, JwtSecretWrapper},
        ExtraConfig,
    };

    const TEST_BLOCK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/signed-mainnet-beacon-block.bin.ssz"
    ));

    pub fn get_test_config() -> Result<Option<ExtraConfig>> {
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
        let network = env::var("NETWORK").unwrap();

        Ok(Some(ExtraConfig {
            engine_api: Url::parse(&engine_api)?,
            execution_api: Url::parse(&execution_api)?,
            beacon_api: Url::parse(&beacon_api)?,
            fee_recipient: address!("dd5DFB73a16B21a6D6bAfF278Fe05D97f71ACfD3"),
            builder_private_key: BlsSecretKeyWrapper::from(
                "0x6b845831c99c6bf43364bee624447d39698465df5c07f2cc4dca6e0acfbe46cd",
            ),
            engine_jwt: JwtSecretWrapper::try_from(jwt_secret.as_str())?,
            network: network.clone().into(),
            auth_token,
        }))
    }

    pub fn gen_test_tx_request(
        sender: Address,
        chain_id: u64,
        nonce: Option<u64>,
    ) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(sender)
            // Burn it
            .with_to(Address::ZERO)
            .with_chain_id(chain_id)
            .with_nonce(nonce.unwrap_or(0))
            .with_value(U256::from(100))
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000) // 1 gwei
            .with_max_fee_per_gas(20_000_000_000)
    }

    /// Reads and decodes a signed beacon block from `testdata`.
    pub fn read_test_block() -> SignedBeaconBlockDeneb<MainnetEthSpec> {
        SignedBeaconBlockDeneb::from_ssz_bytes(TEST_BLOCK).unwrap()
    }

    /// Reads and decodes the transactions root and the transactions from the test block.
    pub fn read_test_transactions() -> (B256, Vec<Bytes>) {
        let test_block = read_test_block();

        let transactions = test_block.message.body.execution_payload.transactions().unwrap();

        let transactions: Vec<Bytes> =
            transactions.into_iter().map(|tx| Bytes::from(tx.to_vec())).collect();

        let transactions_root = test_block
            .message
            .body
            .execution_payload
            .to_execution_payload_header()
            .transactions_root();

        (B256::from_slice(transactions_root.as_ref()), transactions)
    }
}
