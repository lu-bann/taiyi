use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    interface AllocationManager {
        /**
         * @notice Parameters used to register for an AVS's operator sets
         * @param avs the AVS being registered for
         * @param operatorSetIds the operator sets within the AVS to register for
         * @param data extra data to be passed to the AVS to complete registration
         */
        struct RegisterParams {
            address avs;
            uint32[] operatorSetIds;
            bytes data;
        }

        /**
         * @notice Register an operator for one or more operator sets within a given AVS
         * @param operator The operator to register
         * @param params Registration parameters including AVS address, operator set IDs, and any custom data
         */
        function registerForOperatorSets(
            address operator,
            RegisterParams calldata params
        ) external;
    }
}
