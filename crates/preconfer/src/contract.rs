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
                    bytes underwriterSignedBlockspaceAllocation;
                    bytes rawTx;
                    bytes underwriterSignedRawTx;
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

use alloy_primitives::{Bytes, PrimitiveSignature, U256};
use taiyi_primitives::PreconfRequestTypeB;

pub fn to_solidity_type(
    request: PreconfRequestTypeB,
    blockspace_allocation_sig_user: PrimitiveSignature,
    blockspace_allocation_sig_underwriter: PrimitiveSignature,
    raw_tx: Bytes,
    underwriter_signed_raw_tx: PrimitiveSignature,
) -> core::TaiyiCore::PreconfRequestBType {
    core::TaiyiCore::PreconfRequestBType {
        blockspaceAllocation: core::TaiyiCore::BlockspaceAllocation {
            gasLimit: U256::from(request.allocation.gas_limit),
            sender: request.signer(),
            recipient: request.allocation.recipient,
            deposit: request.allocation.deposit,
            tip: request.allocation.tip,
            targetSlot: U256::from(request.allocation.target_slot),
            blobCount: U256::from(request.allocation.blob_count),
        },
        blockspaceAllocationSignature: blockspace_allocation_sig_user.as_bytes().into(),
        underwriterSignedBlockspaceAllocation: blockspace_allocation_sig_underwriter
            .as_bytes()
            .into(),
        rawTx: raw_tx,
        underwriterSignedRawTx: underwriter_signed_raw_tx.as_bytes().into(),
    }
}
