use std::time::SystemTime;

use alloy_eips::eip2718::Encodable2718;
use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, ChainId};
use alloy_provider::{utils::Eip1559Estimation, Provider};
use alloy_rpc_types_beacon::constants::BLS_DST_SIG;
use alloy_transport::Transport;
use ethereum_consensus::{
    crypto::{PublicKey as BlsPublicKey, Signature},
    deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, Context, Transaction},
    ssz::prelude::ByteList,
};
use eyre::Context as _;
use reqwest::Url;
use taiyi_primitives::{ConstraintsMessage, PreconfRequest, SignableBLS, SignedConstraints};
use tracing::{error, info};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];
pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];

use crate::metrics::preconfer::{PRECONF_CONSTRAINTS_SENT_TIME, RELAY_STATUS_CODE};

/// Client used by commit modules to request signatures via the Signer API
#[derive(Clone)]
pub struct ConstraintClient {
    urls: Vec<Url>,
    client: reqwest::Client,
}

impl ConstraintClient {
    pub fn new(relay_server_address: Vec<String>) -> eyre::Result<Self> {
        let client = reqwest::Client::builder().build()?;

        let urls = relay_server_address
            .into_iter()
            .map(|url| Url::parse(&url).wrap_err("invalid relay server address"))
            .collect::<Result<Vec<Url>, _>>()?;

        Ok(Self { urls, client })
    }

    pub async fn send_set_constraints(
        &self,
        constraints: Vec<SignedConstraints>,
        slot_start_timestamp: u64,
    ) -> eyre::Result<()> {
        for url in self.urls.iter() {
            let url = url.join("/constraints/v1/builder/constraints")?;

            let response = self.client.post(url.clone()).json(&constraints).send().await?;
            let code = response.status();
            RELAY_STATUS_CODE.with_label_values(&[code.as_str(), url.as_str()]).inc();
            for constraint in constraints.iter() {
                let now = SystemTime::now();
                let slot_diff_time = now
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("get system error")
                    .as_millis() as f64
                    - (slot_start_timestamp * 1000) as f64;
                PRECONF_CONSTRAINTS_SENT_TIME
                    .with_label_values(&[constraint.message.slot.to_string().as_str()])
                    .observe(slot_diff_time);
            }

            let body = response.bytes().await.wrap_err("failed to parse response")?;
            let body = String::from_utf8_lossy(&body);

            if code.is_success() {
                info!("Constraints submitted successfully");
            } else {
                error!("Failed to submit constraints {} {}", body, code);
            }
        }
        Ok(())
    }
}

pub fn compute_domain_custom(chain: &Context, domain_mask: [u8; 4]) -> [u8; 32] {
    #[derive(Debug, TreeHash)]
    struct ForkData {
        fork_version: [u8; 4],
        genesis_validators_root: [u8; 32],
    }

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_mask);

    let fork_version = chain.genesis_fork_version;
    let fd = ForkData { fork_version, genesis_validators_root: GENESIS_VALIDATORS_ROOT };
    let fork_data_root = fd.tree_hash_root().0;

    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain
}

pub fn compute_signing_root_custom(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    #[derive(Default, Debug, TreeHash)]
    struct SigningData {
        object_root: [u8; 32],
        signing_domain: [u8; 32],
    }

    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root().0
}

pub async fn preconf_reqs_to_constraints(
    preconf_reqs: Vec<PreconfRequest>,
    bls_sk: &blst::min_pk::SecretKey,
    context: &Context,
    slot: u64,
) -> eyre::Result<Vec<SignedConstraints>> {
    let mut txs = Vec::new();
    for preconf_req in preconf_reqs {
        if let Some(tx) = preconf_req.transaction {
            let mut tx_bytes = Vec::new();
            tx.encode_2718(&mut tx_bytes);
            let tx_ref: &[u8] = tx_bytes.as_ref();
            let tx_bytes: ByteList<MAX_BYTES_PER_TRANSACTION> =
                tx_ref.try_into().expect("tx bytes too big");
            txs.push(tx_bytes);
        }
    }

    let bls_pk = bls_sk.sk_to_pk().to_bytes();
    let message = ConstraintsMessage {
        pubkey: BlsPublicKey::try_from(bls_pk.as_ref()).expect("key error"),
        slot,
        top: true,
        transactions: txs.try_into().expect("tx too big"),
    };

    let digest = message.digest();
    let domain = compute_domain_custom(context, COMMIT_BOOST_DOMAIN);
    let root = compute_signing_root_custom(digest.tree_hash_root().0, domain);
    let signature = bls_sk.sign(root.as_ref(), BLS_DST_SIG, &[]).to_bytes();
    let signature = Signature::try_from(signature.as_ref()).expect("signature error");

    let constraints: Vec<SignedConstraints> = vec![SignedConstraints { message, signature }];
    Ok(constraints)
}
