use alloy_eips::eip2718::Encodable2718;
use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_transport::Transport;
use ethereum_consensus::ssz::prelude::{ByteList, List};
use taiyi_primitives::{
    Constraint, ConstraintsMessage, PreconfRequest, MAX_TRANSACTIONS_PER_BLOCK,
};
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
                uint256 target_slot;
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
pub use core::TaiyiCore::TaiyiCoreInstance;

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
                target_slot: req.tip_tx.target_slot,
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

pub async fn preconf_reqs_to_constraints<T, P>(
    preconf_reqs: Vec<PreconfRequest>,
    taiyi_core_address: Address,
    provider: P,
    wallet: EthereumWallet,
    slot: u64,
) -> ConstraintsMessage
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    let contract = core::TaiyiCore::TaiyiCoreInstance::new(taiyi_core_address, provider);
    let preconf_reqs: Vec<core::PreconfRequest> =
        preconf_reqs.into_iter().map(|req| req.into()).collect();
    let tx = contract.batchSettleRequests(preconf_reqs).into_transaction_request();

    let tx_envelope: Vec<u8> = tx.build(&wallet).await.expect("build tx").encoded_2718();
    let tx_envelope_ref: &[u8] = tx_envelope.as_ref();
    let constraint: List<Constraint, MAX_TRANSACTIONS_PER_BLOCK> = vec![Constraint {
        tx: ByteList::<1_073_741_824usize>::try_from(tx_envelope_ref).expect("tx too big"),
    }]
    .try_into()
    .expect("constraint");
    let constraints = vec![constraint].try_into().expect("constraints");
    ConstraintsMessage { slot, constraints }
}
