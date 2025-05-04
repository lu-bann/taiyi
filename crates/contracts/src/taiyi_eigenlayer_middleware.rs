use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    interface TaiyiValidatorAVSEigenlayerMiddleware {
        function deregisterOperator() public;
        function registerValidators(bytes[][] calldata valPubKeys,address[] calldata podOwners,bytes[] calldata delegatedUnderwriters) external;
        function getStrategiesAndStakes(address operator) external view returns (address[] memory strategyAddresses, uint256[] memory stakeAmounts);
    }

}
