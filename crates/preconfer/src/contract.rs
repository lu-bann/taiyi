pub mod core {
    use alloy_sol_types::sol;

    sol! {
            #[sol(rpc)]
            contract TaiyiCore {
                #[derive(Debug)]
                function lockBlockOf(address user) public view returns (uint256);
                #[derive(Debug)]
                function balanceOf(address user) public view returns (uint256);

                #[derive(Debug)]
                struct BlockspaceAllocation {
                    uint256 gasLimit;
                    address sender;
                    address recipient;
                    uint256 deposit;
                    uint256 tip;
                    uint256 targetSlot;
                    uint256 blobCount;
                }

                #[derive(Debug)]
                struct PreconfRequestBType {
                    BlockspaceAllocation blockspaceAllocation;
                    bytes blockspaceAllocationSignature;
                    bytes gatewaySignedBlockspaceAllocation;
                    bytes rawTx;
                    bytes gatewaySignedRawTx;
                }

                #[derive(Debug)]
                function getTip(PreconfRequestBType calldata preconfRequestBType) public payable nonReentrant;

                #[derive(Debug)]
                function exhaust(PreconfRequestBType calldata preconfRequestBType) external onlyOwner;

                #[derive(Debug)]
                function sponsorEthBatch(
                    address[] calldata recipients,
                    uint256[] calldata amounts
                )
                    external
                    payable
                    onlyOwner;
            }
    }
}

use alloy_primitives::{Address, Bytes, PrimitiveSignature, U256};
use taiyi_primitives::PreconfRequestTypeB;

pub fn to_solidity_type(
    request: PreconfRequestTypeB,
    blockspace_allocation_sig_user: PrimitiveSignature,
    blockspace_allocation_sig_gateway: PrimitiveSignature,
    raw_tx: Bytes,
    gateway_signed_raw_tx: PrimitiveSignature,
    taiyi_core: Address,
) -> core::TaiyiCore::PreconfRequestBType {
    core::TaiyiCore::PreconfRequestBType {
        blockspaceAllocation: core::TaiyiCore::BlockspaceAllocation {
            gasLimit: U256::from(request.allocation.gas_limit),
            sender: request.signer(),
            recipient: taiyi_core,
            deposit: request.allocation.deposit,
            tip: request.allocation.tip,
            targetSlot: U256::from(request.allocation.target_slot),
            blobCount: U256::from(request.allocation.blob_count),
        },
        blockspaceAllocationSignature: blockspace_allocation_sig_user.as_bytes().into(),
        gatewaySignedBlockspaceAllocation: blockspace_allocation_sig_gateway.as_bytes().into(),
        rawTx: raw_tx,
        gatewaySignedRawTx: gateway_signed_raw_tx.as_bytes().into(),
    }
}
