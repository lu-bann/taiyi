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
    interface TaiyiValidatorAVSEigenlayerMiddleware {
        function registerOperatorToAVS(
            address operator,
            SignatureWithSaltAndExpiry calldata operatorSignature
        );
        function deregisterOperator() public;
        function registerValidators(bytes[][] calldata valPubKeys,address[] calldata podOwners,bytes[] calldata delegatedGateways) external;
    }
}
