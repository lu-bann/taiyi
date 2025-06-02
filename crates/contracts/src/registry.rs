use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    enum OperatorStatus {
        NEVER_REGISTERED,
        REGISTERED,
        DEREGISTERED
    }


    struct OperatorInfo {
        bytes32 operatorId;
        OperatorStatus status;
    }
    #[sol(rpc)]
    interface TaiyiCoordinator {
        function getOperator(
            address operator,
        )
            external
            view
            returns (OperatorInfo memory);
    }
}
