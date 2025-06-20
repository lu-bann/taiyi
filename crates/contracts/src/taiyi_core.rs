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
