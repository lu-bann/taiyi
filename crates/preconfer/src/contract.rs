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
use taiyi_primitives::{ConstraintsMessage, PreconfRequest, SignableBLS, SignedConstraints};
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
            }
    }
}

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
