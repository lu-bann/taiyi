// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { OwnableUpgradeable } from "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { EnumerableMap } from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { TaiyiProposerRegistry } from "./TaiyiProposerRegistry.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";

import { IStrategyManager } from "@eigenlayer-contracts/contracts/interfaces/IStrategyManager.sol";
import { IAVSDirectory } from "@eigenlayer-contracts/contracts/interfaces/IAVSDirectory.sol";
import { IDelegationManager } from "@eigenlayer-contracts/contracts/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "@eigenlayer-contracts/contracts/interfaces/ISignatureUtils.sol";
import { IStrategy } from "@eigenlayer-contracts/contracts/interfaces/IStrategy.sol";
import { AVSDirectoryStorage } from "@eigenlayer-contracts/contracts/core/AVSDirectoryStorage.sol";
import { DelegationManagerStorage } from "@eigenlayer-contracts/contracts/core/DelegationManagerStorage.sol";
import { StrategyManagerStorage } from "@eigenlayer-contracts/contracts/core/StrategyManagerStorage.sol";
import { IServiceManager } from "@eigenlayer-middleware/interfaces/IServiceManager.sol";

/// @title EigenLayerMiddleware
/// @notice Middleware contract for integrating with EigenLayer and managing operators/strategies
/// @dev Implements IServiceManager interface and handles operator registration and strategy management
contract EigenLayerMiddleware is OwnableUpgradeable, UUPSUpgradeable, IServiceManager {
    using EnumerableSet for EnumerableSet.AddressSet;

    // ========= STORAGE VARIABLES =========

    /// @notice Start timestamp of the first epoch
    uint48 public START_TIMESTAMP;

    /// @notice TaiyiProposerRegistry contract instance
    TaiyiProposerRegistry public proposerRegistry;

    /// @notice EigenLayer AVS Directory contract
    IAVSDirectory public AVS_DIRECTORY;

    /// @notice EigenLayer Delegation Manager contract
    DelegationManagerStorage public DELEGATION_MANAGER;

    /// @notice EigenLayer Strategy Manager contract
    StrategyManagerStorage public STRATEGY_MANAGER;

    /// @notice Set of allowed EigenLayer strategies
    EnumerableSet.AddressSet private strategies;

    /// @notice Name hash of the restaking protocol for identifying the instance
    bytes32 public NAME_HASH;

    // ========= ERRORS =========

    error AlreadyRegistered();
    error NotRegistered();
    error NotOperator();
    error InvalidQuery();
    error StrategyNotAllowed();

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the AVS Directory contract address
    /// @return Address of the AVS Directory contract
    function avsDirectory() external view override returns (address) {
        return address(AVS_DIRECTORY);
    }

    /// @notice Get the strategies an operator has restaked in
    /// @param operator Address of the operator
    /// @return Array of strategy addresses the operator has restaked in
    function getOperatorRestakedStrategies(address operator) external view override returns (address[] memory) {
        address[] memory restakedStrategies = new address[](strategies.length());
        uint256 count = 0;

        for (uint256 i = 0; i < strategies.length(); i++) {
            address strategy = strategies.at(i);
            if (DELEGATION_MANAGER.operatorShares(operator, IStrategy(strategy)) > 0) {
                restakedStrategies[count] = strategy;
                count++;
            }
        }

        // Resize array to actual count
        assembly {
            mstore(restakedStrategies, count)
        }
        return restakedStrategies;
    }

    /// @notice Get all strategies that can be restaked
    /// @return Array of all registered strategy addresses
    function getRestakeableStrategies() external view override returns (address[] memory) {
        uint256 length = strategies.length();
        address[] memory restakeableStrategies = new address[](length);

        for (uint256 i = 0; i < length; i++) {
            restakeableStrategies[i] = strategies.at(i);
        }

        return restakeableStrategies;
    }

    // ========= INTERNAL FUNCTIONS =========

    /// @notice Internal helper to check if a map entry was active at a given timestamp
    /// @param enabledTime Timestamp when entry was enabled
    /// @param disabledTime Timestamp when entry was disabled
    /// @param timestamp Timestamp to check against
    /// @return bool True if entry was active at timestamp
    function _wasEnabledAt(uint48 enabledTime, uint48 disabledTime, uint48 timestamp) private pure returns (bool) {
        return enabledTime != 0 && enabledTime <= timestamp && (disabledTime == 0 || disabledTime >= timestamp);
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Initialize the contract
    /// @param _owner Address of contract owner
    /// @param _proposerRegistry Address of proposer registry contract
    /// @param _avsDirectory Address of AVS directory contract
    /// @param _delegationManager Address of delegation manager contract
    /// @param _strategyManager Address of strategy manager contract
    function initialize(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager
    )
        public
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        transferOwnership(_owner);

        proposerRegistry = TaiyiProposerRegistry(_proposerRegistry);
        START_TIMESTAMP = uint48(block.timestamp);

        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_delegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_strategyManager);
        NAME_HASH = keccak256("EIGENLAYER");
    }

    /// @notice Register a strategy to work in the protocol
    /// @param strategy The EigenLayer strategy address
    function registerStrategy(address strategy) public onlyOwner {
        if (strategies.contains(strategy)) {
            revert AlreadyRegistered();
        }

        if (!STRATEGY_MANAGER.strategyIsWhitelistedForDeposit(IStrategy(strategy))) {
            revert StrategyNotAllowed();
        }

        strategies.add(strategy);
    }

    /// @notice Deregister a strategy from working in the protocol
    /// @param strategy The EigenLayer strategy address
    function deregisterStrategy(address strategy) public onlyOwner {
        if (!strategies.contains(strategy)) {
            revert NotRegistered();
        }

        strategies.remove(strategy);
    }

    /// @notice Allow an operator to signal opt-in to the protocol
    /// @param rpc The RPC URL of the operator
    /// @param operatorSignature The operator's signature
    function registerOperator(
        string calldata rpc,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    )
        public
    {
        if (proposerRegistry.isOperatorRegistered(msg.sender)) {
            revert AlreadyRegistered();
        }

        if (!DELEGATION_MANAGER.isOperator(msg.sender)) {
            revert NotOperator();
        }

        // Register the operator to the AVS directory for this AVS
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        // Register the operator in the proposer registry
        proposerRegistry.registerOperator(msg.sender, rpc, address(this));
    }

    /// @notice Deregister an operator from the protocol
    function deregisterOperator() public {
        if (!proposerRegistry.isOperatorRegistered(msg.sender)) {
            revert NotRegistered();
        }

        // Deregister the operator from the AVS directory
        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);

        // Deregister the operator in the proposer registry
        proposerRegistry.deregisterOperator(msg.sender);
    }

    /// @notice Updates the metadata URI for the AVS
    /// @param metadataURI The new metadata URI
    function updateAVSMetadataURI(string calldata metadataURI) public onlyOwner {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }

    /// @notice Deregister an operator from the AVS
    /// @param operator Address of operator to deregister
    function deregisterOperatorFromAVS(address operator) external override {
        require(msg.sender == operator, "Only operator can deregister");
        AVS_DIRECTORY.deregisterOperatorFromAVS(operator);
    }

    /// @notice Register an operator to the AVS
    /// @param operator Address of operator to register
    /// @param operatorSignature Signature from operator
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    )
        external
        override
    {
        require(msg.sender == operator, "Only operator can register");
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
    }
}
