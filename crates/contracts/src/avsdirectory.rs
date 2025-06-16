use alloy_sol_types::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]

    interface AVSDirectory {

        function calculateOperatorAVSRegistrationDigestHash(
            address operator,
            address avs,
            bytes32 salt,
            uint256 expiry
        ) external view returns (bytes32);

    }
);
