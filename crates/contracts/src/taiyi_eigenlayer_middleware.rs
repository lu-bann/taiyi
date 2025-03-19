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
        function getStrategiesAndStakes(address operator) external view returns (address[] memory strategyAddresses, uint256[] memory stakeAmounts);
    }

    #[sol(rpc)]
    interface TaiyiGatewayAVSEigenlayerMiddleware {
        function registerOperatorToAVSWithPubKey(
            address operator,
            SignatureWithSaltAndExpiry calldata operatorSignature,
            bytes calldata operatorBLSPubKey
        );
    }
}
