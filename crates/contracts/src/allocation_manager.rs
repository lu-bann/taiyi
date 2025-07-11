use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    struct SignatureWithSaltAndExpiry {
        bytes signature;
        bytes32 salt;
        uint256 expiry;
    }
    #[allow(missing_docs)]
    #[sol(rpc)]
    struct AllocateParams {
        OperatorSet operatorSet;
        address[] strategies;
        uint64[] newMagnitudes;
    }

    struct OperatorSet {
        address avs;
        uint32 id;
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

        function modifyAllocations(
            address operator,
            AllocateParams[] memory params
        ) external;
    }
);
