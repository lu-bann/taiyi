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
use taiyi_primitives::{
    inclusion_request::InclusionRequest, ConstraintsMessage, PreconfRequest, SignableBLS,
    SignedConstraints,
};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];
pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];
pub mod core {
    use alloy_sol_types::sol;

    sol! {
            #[derive(Debug)]
            struct TipTx {
                uint256 gasLimit;
                address from;
                address to;
                uint256 prePay;
                uint256 afterPay;
                uint256 nonce;
                uint256 targetSlot;
            }

            #[derive(Debug)]
            struct PreconfTx {
                address from;
                address to;
                uint256 value;
                bytes callData;
                uint256 callGasLimit;
                uint256 nonce;
                bytes signature;
            }

            #[derive(Debug)]
            struct InclusionTx {
                address from;
                address to;
                uint256 value;
                bytes callData;
            }

            #[derive(Debug)]
            struct PreconfRequest {
                TipTx tipTx;
                PreconfTx preconfTx;
                bytes tipTxSignature;
                bytes preconferSignature;
                bytes preconfReqSignature;
            }

            #[sol(rpc)]
            contract TaiyiCore {
                #[derive(Debug)]
                function batchSettleRequests(PreconfRequest[] calldata preconfReqs) external payable;
                #[derive(Debug)]
                function exhaust(PreconfRequest calldata preconfReq) external;
                #[derive(Debug)]
                function lockBlockOf(address user) public view returns (uint256);
                #[derive(Debug)]
                function balanceOf(address user) public view returns (uint256);
                #[derive(Debug)]
                function batchSettleRequestsV2(InclusionTx[] calldata inclusionReqs) external payable;
            }
    }
}
pub use core::TaiyiCore::TaiyiCoreInstance;
use std::str::FromStr;

impl From<PreconfRequest> for core::PreconfRequest {
    fn from(req: PreconfRequest) -> Self {
        let preconf_tx = req.preconf_tx.expect("preconf_tx is none");
        core::PreconfRequest {
            tipTx: core::TipTx {
                gasLimit: req.tip_tx.gas_limit,
                from: req.tip_tx.from,
                to: req.tip_tx.to,
                prePay: req.tip_tx.pre_pay,
                afterPay: req.tip_tx.after_pay,
                nonce: req.tip_tx.nonce,
                targetSlot: req.tip_tx.target_slot,
            },
            preconfTx: core::PreconfTx {
                from: preconf_tx.from,
                to: preconf_tx.to,
                value: preconf_tx.value,
                callData: preconf_tx.call_data,
                callGasLimit: preconf_tx.call_gas_limit,
                nonce: preconf_tx.nonce,
                signature: preconf_tx.signature,
            },
            tipTxSignature: Bytes::from(req.tip_tx_signature.as_bytes()),
            preconferSignature: Bytes::from(
                req.preconfer_signature.expect("preconfer_signature is none").as_bytes(),
            ),
            preconfReqSignature: Bytes::from(
                req.preconf_req_signature.expect("preconf_req_signature is none").as_bytes(),
            ),
        }
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

pub async fn _preconf_reqs_to_constraints<T, P>(
    preconf_reqs: Vec<PreconfRequest>,
    taiyi_core_address: Address,
    provider: P,
    wallet: EthereumWallet,
    bls_sk: &blst::min_pk::SecretKey,
    context: &Context,
) -> eyre::Result<Vec<SignedConstraints>>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    // FIXME: check all slots are the same
    let slot: u64 = preconf_reqs[0].tip_tx.target_slot.to();
    let chain_id = provider.get_chain_id().await?;
    let contract = core::TaiyiCore::TaiyiCoreInstance::new(taiyi_core_address, provider.clone());

    let preconf_reqs: Vec<core::PreconfRequest> =
        preconf_reqs.into_iter().map(|req| req.into()).collect();
    let mut tx = contract.batchSettleRequests(preconf_reqs).into_transaction_request();
    let estimate_gas = provider.estimate_gas(&tx).await?;
    let gas_limit = estimate_gas + 100000;
    let Eip1559Estimation { max_fee_per_gas, max_priority_fee_per_gas } =
        provider.estimate_eip1559_fees(None).await?;
    let nonce = provider.get_transaction_count(wallet.default_signer().address()).await?;
    tx.set_gas_limit(gas_limit);
    tx.set_max_fee_per_gas(max_fee_per_gas);
    tx.set_max_priority_fee_per_gas(max_priority_fee_per_gas);
    tx.set_nonce(nonce);
    tx.set_chain_id(ChainId::from(chain_id));

    let tx_envelope: Vec<u8> = tx.build(&wallet).await.expect("build tx").encoded_2718();
    let tx_envelope_ref: &[u8] = tx_envelope.as_ref();
    let tx_envelope_bl: Transaction<MAX_BYTES_PER_TRANSACTION> =
        tx_envelope_ref.try_into().expect("bytelist");
    let bls_pk = bls_sk.sk_to_pk().to_bytes();
    let message = ConstraintsMessage {
        pubkey: BlsPublicKey::try_from(bls_pk.as_ref()).expect("key error"),
        slot,
        top: true,
        transactions: vec![tx_envelope_bl].try_into().expect("tx too big"),
    };
    let digest = message.digest();
    let domain = compute_domain_custom(context, COMMIT_BOOST_DOMAIN);
    let root = compute_signing_root_custom(digest.tree_hash_root().0, domain);
    let signature = bls_sk.sign(root.as_ref(), BLS_DST_SIG, &[]).to_bytes();
    let signature = Signature::try_from(signature.as_ref()).expect("signature error");

    let constraints: Vec<SignedConstraints> = vec![SignedConstraints { message, signature }];
    Ok(constraints)
}

pub async fn inclusion_reqs_to_constraints(
    inclusion_reqs: Vec<InclusionRequest>,
    wallet: EthereumWallet,
    bls_sk: &blst::min_pk::SecretKey,
    context: &Context,
) -> eyre::Result<Vec<SignedConstraints>> {
    let slot = inclusion_reqs.first().expect("slot is none").slot;

    let mut txs = Vec::new();
    for incl_req in inclusion_reqs {
        for full_tx in incl_req.txs {
            let mut tx_bytes = Vec::new();
            full_tx.tx.encode_enveloped(&mut tx_bytes);
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
