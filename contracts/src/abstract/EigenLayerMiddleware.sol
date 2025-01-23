// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { EnumerableMap } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { IGatewayAVS } from "../interfaces/IGatewayAVS.sol";
import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { IValidatorAVS } from "../interfaces/IValidatorAVS.sol";

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

/// @title Abstract base contract for EigenLayer AVS modules (GatewayAVS or ValidatorAVS).
/// @dev Both GatewayAVS and ValidatorAVS should inherit from this contract.
abstract contract EigenLayerMiddleware is
    OwnableUpgradeable,
    UUPSUpgradeable,
    IServiceManager
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using BitmapUtils for *;

    // ========= STORAGE VARIABLES =========

    /// @notice ProposerRegistry contract instance
    IProposerRegistry public proposerRegistry;

    /// @notice EigenLayer AVS Directory contract
    IAVSDirectory public AVS_DIRECTORY;

    /// @notice EigenLayer EigenPodManager contract
    IEigenPodManager public EIGEN_POD_MANAGER;

    /// @notice EigenLayer Delegation Manager contract
    DelegationManagerStorage public DELEGATION_MANAGER;

    /// @notice EigenLayer Strategy Manager contract
    StrategyManagerStorage public STRATEGY_MANAGER;

    /// @notice EigenLayer Reward Coordinator contract for managing operator rewards
    IRewardsCoordinator public REWARDS_COORDINATOR;

    /// @notice Set of allowed EigenLayer strategies
    EnumerableSet.AddressSet internal strategies;

    /// @notice The address of the entity that can initiate rewards
    address public REWARD_INITIATOR;

    // ========= EVENTS =========

    event RewardsInitiatorUpdated(
        address indexed oldInitiator, address indexed newInitiator
    );
    event AVSDirectorySet(address indexed avsDirectory);

    // ========= ERRORS =========

    error ValidatorNotActiveWithinEigenCore();
    error OperatorAlreadyRegistered();
    error OperatorNotRegistered();
    error CallerNotOperator();
    error InvalidQueryParameters();
    error UnsupportedStrategy();

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

    /// @notice only rewardsInitiator can call createAVSRewardsSubmission
    modifier onlyRewardsInitiator() {
        _checkRewardsInitiator();
        _;
    }

    /// @notice Modifier that restricts function access to operators registered in the proposer registry or the contract owner
    /// @dev Reverts with OperatorNotRegistered if msg.sender is not registered in proposer registry and is not the owner
    modifier onlyRegisteredOperatorOrOwner() {
        if (
            !proposerRegistry.isOperatorRegisteredInGatewayAVS(msg.sender)
                && !proposerRegistry.isOperatorRegisteredInValidatorAVS(msg.sender)
                && msg.sender != owner()
        ) {
            revert OperatorNotRegistered();
        }
        _;
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
    /// @param _rewardCoordinator Address of reward coordinator contract
    /// @param _rewardInitiator Address of reward initiator
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

        proposerRegistry = IProposerRegistry(_proposerRegistry);

        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_delegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_strategyManager);
        EIGEN_POD_MANAGER = IEigenPodManager(_eigenPodManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_rewardCoordinator);
        _setRewardsInitiator(_rewardInitiator);
    }

    /// @notice Register multiple validators for multiple pod owners in a single
    /// transaction
    /// @param valPubKeys Array of arrays containing validator BLS public keys,
    /// where each inner array corresponds to a
    /// pod owner
    /// @param podOwners Array of pod owner addresses, each owning the
    /// validators specified in the corresponding
    /// valPubKeys array
    /// @dev Length of valPubKeys array must match length of podOwners array
    function registerValidators(
        bytes[][] calldata valPubKeys,
        address[] calldata podOwners,
        bytes[] calldata delegatedGateways
    )
        external
    {
        uint256 len = podOwners.length;
        for (uint256 i = 0; i < len; ++i) {
            _registerValidators(valPubKeys[i], podOwners[i], delegatedGateways[i]);
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
        external
        virtual
    {
        _registerOperatorToAvs(operator, operatorSignature);
    }

    /// @notice Deregister an operator from the protocol
    function deregisterOperatorFromAVS(address operator)
        public
        onlyRegisteredOperatorOrOwner
    {
        _deregisterOperatorFromAVS(operator);
    }

    /// @notice Updates the metadata URI for the AVS
    /// @param metadataURI The new metadta URI
    function updateAVSMetadataURI(string calldata metadataURI) public onlyOwner {
        _updateAVSMetadataURI(metadataURI);
    }

    /// @notice Creates operator-directed rewards to split between operators and their delegated stakers
    /// @param operatorDirectedRewardsSubmissions The rewards submissions to process
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
            operatorDirectedRewardsSubmissions
    )
        public
        virtual
    {
        _createOperatorDirectedAVSRewardsSubmission(operatorDirectedRewardsSubmissions);
    }

    /// @notice Forwards a call to Eigenlayer's RewardsCoordinator contract to set the address of
    /// the entity that can call `processClaim` on behalf of this contract.
    /// @param claimer The address of the entity that can call `processClaim` on behalf of the earner
    /// @dev Only callable by the owner.
    function setClaimerFor(address claimer) public virtual onlyOwner {
        _setClaimerFor(claimer);
    }

    // ========= INTERNAL FUNCTIONS =========

    /// @notice Helper function to build an OperatorDirectedRewardsSubmission for a single operator
    /// @dev Reused in both gateway distribution and validator distribution to reduce code duplication
    function _buildOperatorSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata baseSubmission,
        IERC20 token,
        address operator,
        uint256 amount,
        string memory suffixDescription
    )
        internal
        pure
        returns (IRewardsCoordinator.OperatorDirectedRewardsSubmission memory)
    {
        // Build an array with a single reward
        IRewardsCoordinator.OperatorReward[] memory singleReward =
            new IRewardsCoordinator.OperatorReward[](1);

        singleReward[0] =
            IRewardsCoordinator.OperatorReward({ operator: operator, amount: amount });

        // Return final
        return IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: baseSubmission.strategiesAndMultipliers,
            token: token,
            operatorRewards: singleReward,
            startTimestamp: baseSubmission.startTimestamp,
            duration: baseSubmission.duration,
            description: string(
                abi.encodePacked(baseSubmission.description, suffixDescription)
            )
        });
    }

    function _createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions
    )
        internal
        virtual
    { }

    function _setClaimerFor(address claimer) internal {
        REWARDS_COORDINATOR.setClaimerFor(claimer);
    }

    function _checkRewardsInitiator() internal view {
        require(
            msg.sender == REWARD_INITIATOR,
            "EigenLayerMiddleware.onlyRewardsInitiator: caller is not the rewards initiator"
        );
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    function _setRewardsInitiator(address newRewardsInitiator) internal {
        REWARD_INITIATOR = newRewardsInitiator;
        emit RewardsInitiatorUpdated(REWARD_INITIATOR, newRewardsInitiator);
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
        address podOwner,
        bytes calldata delegatedGatewayPubKey
    )
        internal
        virtual
    { }

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
        virtual
    { }

    /// @dev Internal function that deregisters an operator.
    function _deregisterOperatorFromAVS(address operator) internal {
        AVS_DIRECTORY.deregisterOperatorFromAVS(operator);
        proposerRegistry.deregisterOperator(operator);
    }

    /// @dev Internal function that updates the AVS metadata URI.
    function _updateAVSMetadataURI(string calldata metadataURI) internal {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the AVS Directory contract address
    /// @return Address of the AVS Directory contract
    function avsDirectory() external view returns (address) {
        return address(AVS_DIRECTORY);
    }

    /// @notice Get the strategies an operator has restaked in
    /// @param operator Address of the operator
    /// @return Array of strategy addresses the operator has restaked in
    function getOperatorRestakedStrategies(address operator)
        external
        view
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
    function getRestakeableStrategies() external view returns (address[] memory) {
        return strategies.values();
    }

    /// @notice Gets the GatewayAVS address from the registry
    /// @return The address of the GatewayAVS contract
    function getGatewayAVSAddress() public view returns (address) {
        return address(proposerRegistry.gatewayAVS());
    }

    /// @notice Gets the ValidatorAVS address from the registry by AVS type
    /// @return The address of the ValidatorAVS contract
    function getValidatorAVSAddress() public view returns (address) {
        return address(proposerRegistry.validatorAVS());
    }

    /// @notice Gets the GatewayAVS contract instance from the registry
    /// @return The GatewayAVS contract instance
    function getGatewayAVS() public view returns (IGatewayAVS) {
        return IGatewayAVS(proposerRegistry.gatewayAVS());
    }

    /// @notice Gets the ValidatorAVS contract instance from the registry
    /// @return The ValidatorAVS contract instance
    function getValidatorAVS() public view returns (IValidatorAVS) {
        return IValidatorAVS(proposerRegistry.validatorAVS());
    }
}
