use alloy_sol_types::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    struct SignatureWithSaltAndExpiry {
        bytes signature;
        bytes32 salt;
        uint256 expiry;
    }
    #[sol(rpc)]
    interface TaiyiEigenlayerMiddleware {
        function registerOperator(
            SignatureWithSaltAndExpiry calldata operatorSignature
        ) public;
        function deregisterOperator() public;
    }
}
