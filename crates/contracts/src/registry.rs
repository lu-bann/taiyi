use alloy_sol_types::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    enum AVSType {
        GATEWAY,
        VALIDATOR
    }
    #[sol(rpc)]
    interface ProposerRegistry {
        function operatorInfo(
            address operator,
            AVSType avsType
        )
            external
            view
            returns (bytes memory pubKey, bool isActive);
        function getValidatorsForOperator(address operator)
            external
            view
            returns (bytes[] memory);
    }
}
