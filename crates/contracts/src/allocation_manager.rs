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
    interface AllocationManager {
        struct RegisterParams {
            address avs;
            uint32[] operatorSetIds;
            bytes data;
        }
        struct PubkeyRegistrationParams {
            bytes blsPubkey;
            address operator;
            bytes pubkeyRegistrationSignature;
        }

        function registerForOperatorSets(
            address operator,
            RegisterParams calldata params
        ) external;
    }
}
