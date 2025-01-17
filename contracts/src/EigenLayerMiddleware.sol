// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { EnumerableMap } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { TaiyiProposerRegistry } from "./TaiyiProposerRegistry.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";

import { AVSDirectoryStorage } from
    "@eigenlayer-contracts/src/contracts/core/AVSDirectoryStorage.sol";
import { DelegationManagerStorage } from
    "@eigenlayer-contracts/src/contracts/core/DelegationManagerStorage.sol";
import { StrategyManagerStorage } from
    "@eigenlayer-contracts/src/contracts/core/StrategyManagerStorage.sol";
import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IEigenPod } from "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IEigenPodManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPodManager.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IStrategyManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";

import { IServiceManager } from
    "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import { BitmapUtils } from "@eigenlayer-middleware/src/libraries/BitmapUtils.sol";

/// @title EigenLayerMiddleware
/// @notice Middleware contract for integrating with EigenLayer and managing
/// operators/strategies
/// @dev Implements IServiceManager interface and handles operator registration
/// and strategy management
contract EigenLayerMiddleware is OwnableUpgradeable, UUPSUpgradeable, IServiceManager {
    using EnumerableSet for EnumerableSet.AddressSet;
    using BitmapUtils for *;

    // ========= STORAGE VARIABLES =========

    /// @notice TaiyiProposerRegistry contract instance
    TaiyiProposerRegistry public proposerRegistry;

    /// @notice EigenLayer AVS Directory contract
    IAVSDirectory public AVS_DIRECTORY;

    /// @notice EigenLayer EigenPodManager contract
    IEigenPodManager public EIGEN_POD_MANAGER;

    /// @notice EigenLayer Delegation Manager contract
    DelegationManagerStorage public DELEGATION_MANAGER;

    /// @notice EigenLayer Strategy Manager contract
    StrategyManagerStorage public STRATEGY_MANAGER;

    /// @notice EigenLayer Reward Coordinator contract for managing operator rewards
    IRewardsCoordinator internal REWARDS_COORDINATOR;

    /// @notice Set of allowed EigenLayer strategies
    EnumerableSet.AddressSet internal strategies;

    /// @notice The address of the entity that can initiate rewards
    address public REWARD_INITIATOR;

    // ========= ERRORS =========

    error SenderNotPodOwnerOrOperator();
    error ValidatorNotActiveWithinEigenCore();
    error OperatorAlreadyRegistered();
    error OperatorNotRegistered();
    error CallerNotOperator();
    error InvalidQueryParameters();
    error UnsupportedStrategy();

    event RewardsInitiatorUpdated(
        address indexed oldInitiator, address indexed newInitiator
    );

    // ========= EVENTS =========
    event AVSDirectorySet(address indexed avsDirectory);

    // ========= MODIFIERS =========

    /// @notice Modifier that restricts function access to operators registered
    /// in EigenLayer core
    /// @dev Reverts with CallerNotOperator if msg.sender is not an EigenLayer
    /// operator
    modifier onlyEigenCoreOperator() {
        if (!DELEGATION_MANAGER.isOperator(msg.sender)) {
            revert CallerNotOperator();
        }
        _;
    }

    /// @notice Modifier that restricts function access to operators registered
    /// in the proposer registry
    /// @dev Reverts with OperatorNotRegistered if msg.sender is not registered
    /// in proposer registry
    modifier onlyRegisteredOperator() {
        if (!proposerRegistry.isOperatorRegistered(msg.sender)) {
            revert OperatorNotRegistered();
        }
        _;
    }

    /// @notice Modifier that restricts function access to operators not registered
    /// in the proposer registry
    /// @dev Reverts with OperatorAlreadyRegistered if msg.sender is already registered
    /// in proposer registry
    modifier onlyNonRegisteredOperator() {
        if (proposerRegistry.isOperatorRegistered(msg.sender)) {
            revert OperatorAlreadyRegistered();
        }
        _;
    }

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the AVS Directory contract address
    /// @return Address of the AVS Directory contract
    function avsDirectory() external view override returns (address) {
        return address(AVS_DIRECTORY);
    }

    // todo: add storage + add reward distribution logic

    /// @notice Get the strategies an operator has restaked in
    /// @param operator Address of the operator
    /// @return Array of strategy addresses the operator has restaked in
    function getOperatorRestakedStrategies(address operator)
        external
        view
        override
        returns (address[] memory)
    {
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
    function getRestakeableStrategies()
        external
        view
        override
        returns (address[] memory)
    {
        return strategies.values();
    }

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Sets the rewards initiator address
    /// @param newRewardsInitiator The new rewards initiator address
    /// @dev only callable by the owner
    function setRewardsInitiator(address newRewardsInitiator) external onlyOwner {
        _setRewardsInitiator(newRewardsInitiator);
    }

    /// @notice Initialize the contract
    /// @param _owner Address of contract owner
    /// @param _proposerRegistry Address of proposer registry contract
    /// @param _avsDirectory Address of AVS directory contract
    /// @param _delegationManager Address of delegation manager contract
    /// @param _strategyManager Address of strategy manager contract
    /// @param _eigenPodManager Address of eigen pod manager contract
    function initialize(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator
    )
        public
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        transferOwnership(_owner);

        proposerRegistry = TaiyiProposerRegistry(_proposerRegistry);

        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_delegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_strategyManager);
        EIGEN_POD_MANAGER = IEigenPodManager(_eigenPodManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_rewardCoordinator);

        _setRewardsInitiator(_rewardInitiator);
    }

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Register multiple validators for multiple pod owners in a single
    /// transaction
    /// @param valPubKeys Array of arrays containing validator BLS public keys,
    /// where each inner array corresponds to a
    /// pod owner
    /// @param podOwners Array of pod owner addresses, each owning the
    /// validators specified in the corresponding
    /// valPubKeys array
    /// @dev Length of valPubKeys array must match length of podOwners array
    function registerValidator(
        bytes[][] calldata valPubKeys,
        address[] calldata podOwners
    )
        external
    {
        uint256 len = podOwners.length;
        for (uint256 i = 0; i < len; ++i) {
            _registerValidators(valPubKeys[i], podOwners[i]);
        }
    }

    /// @dev Sets the AVS directory, restricted to contract owner.
    function setAVSDirectory(IAVSDirectory avsDirectory_) external onlyOwner {
        _setAVSDirectory(avsDirectory_);
    }

    /// @notice Register a strategy to work in the protocol
    /// @param strategy The EigenLayer strategy address
    function registerStrategy(address strategy) public onlyOwner {
        _registerStrategy(strategy);
    }

    /// @notice Deregister a strategy from working in the protocol
    /// @param strategy The EigenLayer strategy address
    function deregisterStrategy(address strategy) public onlyOwner {
        _deregisterStrategy(strategy);
    }

    /// @notice Allow an operator to signal opt-in to the protocol
    /// @param operatorSignature The operator's signature
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    )
        public
        onlyEigenCoreOperator
        onlyNonRegisteredOperator
    {
        _registerOperatorToAvs(operator, operatorSignature);
    }

    /// @notice Deregister an operator from the protocol
    function deregisterOperatorFromAVS(address operator) public onlyRegisteredOperator {
        _deregisterOperatorFromAVS(operator);
    }

    /// @notice Updates the metadata URI for the AVS
    /// @param metadataURI The new metadata URI
    function updateAVSMetadataURI(string calldata metadataURI) public onlyOwner {
        _updateAVSMetadataURI(metadataURI);
    }

    // ========= INTERNAL FUNCTIONS =========

    /// @notice Internal helper to check if a map entry was active at a given
    /// timestamp
    /// @param enabledTime Timestamp when entry was enabled
    /// @param disabledTime Timestamp when entry was disabled
    /// @param timestamp Timestamp to check against
    /// @return bool True if entry was active at timestamp
    function _wasEnabledAt(
        uint48 enabledTime,
        uint48 disabledTime,
        uint48 timestamp
    )
        private
        pure
        returns (bool)
    {
        return enabledTime != 0 && enabledTime <= timestamp
            && (disabledTime == 0 || disabledTime >= timestamp);
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    function _setRewardsInitiator(address newRewardsInitiator) internal {
        emit RewardsInitiatorUpdated(REWARD_INITIATOR, newRewardsInitiator);
        REWARD_INITIATOR = newRewardsInitiator;
    }

    /// @dev Internal function to set the AVS directory.
    function _setAVSDirectory(IAVSDirectory avsDirectory_) internal {
        AVS_DIRECTORY = avsDirectory_;
        emit AVSDirectorySet(address(AVS_DIRECTORY));
    }

    /// @notice Internal function to register multiple validators for a pod
    /// owner
    /// @dev Only the pod owner or their delegated operator can register
    /// validators
    /// @param valPubKeys Array of validator BLS public keys to register
    /// @param podOwner Address of the EigenPod owner
    function _registerValidators(
        bytes[] calldata valPubKeys,
        address podOwner
    )
        internal
    {
        // Check caller is either pod owner or their delegated operator
        if (
            msg.sender != podOwner
                && msg.sender != DELEGATION_MANAGER.delegatedTo(podOwner)
        ) {
            revert SenderNotPodOwnerOrOperator();
        }

        // Get the operator delegated to by the pod owner
        address operator = DELEGATION_MANAGER.delegatedTo(podOwner);

        // Verify operator is registered in proposer registry
        require(
            proposerRegistry.isOperatorRegistered(operator), "Operator not registered"
        );

        // Verify pod owner has an EigenPod
        require(EIGEN_POD_MANAGER.hasPod(podOwner), "No Pod exists");
        IEigenPod pod = EIGEN_POD_MANAGER.getPod(podOwner);

        // Register each validator if they are active in EigenLayer
        uint256 len = valPubKeys.length;
        for (uint256 i = 0; i < len; ++i) {
            // Check validator is active in EigenLayer core
            if (
                pod.validatorPubkeyToInfo(valPubKeys[i]).status
                    != IEigenPod.VALIDATOR_STATUS.ACTIVE
            ) {
                revert ValidatorNotActiveWithinEigenCore();
            }

            // Register validator in proposer registry
            proposerRegistry.registerValidator(valPubKeys[i], operator);
        }
    }

    /// @dev Internal function that registers a strategy.
    function _registerStrategy(address strategy) internal {
        if (strategies.contains(strategy)) {
            revert OperatorAlreadyRegistered();
        }
        if (!STRATEGY_MANAGER.strategyIsWhitelistedForDeposit(IStrategy(strategy))) {
            revert UnsupportedStrategy();
        }
        strategies.add(strategy);
    }

    /// @dev Internal function that deregisters a strategy.
    function _deregisterStrategy(address strategy) internal {
        if (!strategies.contains(strategy)) {
            revert OperatorNotRegistered();
        }
        strategies.remove(strategy);
    }

    /// @dev Internal function that registers an operator.
    function _registerOperatorToAvs(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    )
        internal
    {
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
        proposerRegistry.registerOperator(operator, address(this));
    }

    /// @dev Internal function that deregisters an operator.
    function _deregisterOperatorFromAVS(address operator) internal {
        AVS_DIRECTORY.deregisterOperatorFromAVS(operator);
        proposerRegistry.deregisterOperator(operator);
    }

    /// @dev Internal function that updates the AVS metadata URI.
    function _updateAVSMetadataURI(string calldata metadataURI) internal {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }
}
