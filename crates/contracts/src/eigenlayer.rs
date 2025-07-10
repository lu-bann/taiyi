use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]

    // Reference source code: https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/src/contracts/interfaces/IStrategy.sol
    //
    // NOTE: IERC20 tokens are replaced with `address` because there's no support for it: https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#solidity

    interface IStrategy {

        event ExchangeRateEmitted(uint256 rate);

        event StrategyTokenSet(address token, uint8 decimals);

        function deposit(address token, uint256 amount) external returns (uint256);

        function withdraw(address recipient, address token, uint256 amountShares) external;

        function sharesToUnderlying(uint256 amountShares) external returns (uint256);


        function underlyingToShares(uint256 amountUnderlying) external returns (uint256);

        function userUnderlying(address user) external returns (uint256);


        function shares(address user) external view returns (uint256);


        function sharesToUnderlyingView(uint256 amountShares) external view returns (uint256);

        function underlyingToSharesView(uint256 amountUnderlying) external view returns (uint256);

        function userUnderlyingView(address user) external view returns (uint256);

        #[derive(Debug)]
        function underlyingToken() external view returns (address);

        function totalShares() external view returns (uint256);

        function explanation() external view returns (string memory);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    // Reference source code: https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/src/contracts/interfaces/IStrategyManager.sol
    //
    // NOTE: IERC20 tokens are replaced with `address` because there's no support for it: https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#solidity

    interface IStrategyManager {
        event Deposit(address staker, address token, address strategy, uint256 shares);
        event UpdatedThirdPartyTransfersForbidden(address strategy, bool value);
        event StrategyWhitelisterChanged(address previousAddress, address newAddress);
        event StrategyAddedToDepositWhitelist(address strategy);
        event StrategyRemovedFromDepositWhitelist(address strategy);

        function depositIntoStrategy(address strategy, address token, uint256 amount) external returns (uint256 shares);


        function depositIntoStrategyWithSignature(
            address strategy,
            address token,
            uint256 amount,
            address staker,
            uint256 expiry,
            bytes memory signature
        ) external returns (uint256 shares);

        function removeShares(address staker, address strategy, uint256 shares) external;

        function addShares(address staker, address token, address strategy, uint256 shares) external;

        function withdrawSharesAsTokens(address recipient, address strategy, uint256 shares, address token) external;

        function stakerStrategyShares(address user, address strategy) external view returns (uint256 shares);

        function getDeposits(address staker) external view returns (address[] memory, uint256[] memory);

        function stakerStrategyListLength(address staker) external view returns (uint256);

        function addStrategiesToDepositWhitelist(
            address[] calldata strategiesToWhitelist,
            bool[] calldata thirdPartyTransfersForbiddenValues
        ) external;


        function removeStrategiesFromDepositWhitelist(address[] calldata strategiesToRemoveFromWhitelist) external;

        function setThirdPartyTransfersForbidden(address strategy, bool value) external;

        function delegation() external view returns (address);

        function slasher() external view returns (address);

        function eigenPodManager() external view returns (address);

        function strategyWhitelister() external view returns (address);

        function strategyIsWhitelistedForDeposit(address strategy) external view returns (bool);

        function setStrategyWhitelister(address newStrategyWhitelister) external;

        function thirdPartyTransfersForbidden(address strategy) external view returns (bool);

        function domainSeparator() external view returns (bytes32);
    }
);
