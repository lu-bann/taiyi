use alloy_sol_types::sol;

sol!(
    #[derive(Debug, PartialEq, Eq)]
    struct Fp {
        uint256 a;
        uint256 b;
    }
    #[derive(Debug, PartialEq, Eq)]
    struct Fp2 {
        Fp c0;
        Fp c1;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct G1Point {
        Fp x;
        Fp y;
    }
    #[derive(Debug, PartialEq, Eq)]
    struct G2Point {
        Fp2 x;
        Fp2 y;
    }

    struct SignedRegistration {
        /// BLS public key
        G1Point pubkey;
        /// BLS signature
        G2Point signature;
    }
    #[sol(rpc)]
    interface TaiyiMiddleware {
        function deregisterOperator() public;
        function registerValidators(SignedRegistration[] calldata registrations) external returns (bytes32 registrationRoot);
        function getStrategiesAndStakes(address operator) external view returns (address[] memory strategyAddresses, uint256[] memory stakeAmounts);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    interface BLS {
        function verify(
            bytes memory message,
            G2Point memory signature,
            G1Point memory publicKey,
            bytes memory domainSeparator
        ) public view returns (bool);
    }
);
