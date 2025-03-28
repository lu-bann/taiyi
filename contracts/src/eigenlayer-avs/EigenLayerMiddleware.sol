// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { EnumerableMap } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
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

import { EigenLayerMiddlewareStorage } from "../storage/EigenLayerMiddlewareStorage.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IStrategyManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title EigenLayer Middleware contract
/// @notice This contract is used to manage the registration of operators in EigenLayer core
contract EigenLayerMiddleware is
    OwnableUpgradeable,
    UUPSUpgradeable,
    EigenLayerMiddlewareStorage
{
    using EnumerableSet for EnumerableSet.AddressSet;

    // ========= EVENTS =========

    event AVSDirectorySet(address indexed avsDirectory);
    event RewardsInitiatorUpdated(
        address indexed previousRewardsInitiator, address indexed newRewardsInitiator
    );

    // ========= ERRORS =========

    error ValidatorNotActiveWithinEigenCore();
    error StrategyAlreadyRegistered();
    error StrategyNotRegistered();
    error OperatorNotRegistered();
    error OperatorNotRegisteredInEigenLayer();
    error CallerNotOperator();
    error OnlyRegistryCoordinator();
    error InvalidQueryParameters();
    error UnsupportedStrategy();
    error UseCreateOperatorDirectedAVSRewardsSubmission();
    error UseAllocationManagerForOperatorRegistration();
    error OperatorNotRegisteredInAVS();
    error OperatorIsNotYetRegisteredInValidatorOperatorSet();
    error OperatorIsNotYetRegisteredInUnderwriterOperatorSet();

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

    /// @notice when applied to a function, only allows the RegistryCoordinator to call it
    modifier onlyRegistryCoordinator() {
        require(msg.sender == address(REGISTRY_COORDINATOR), OnlyRegistryCoordinator());
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
            !proposerRegistry.isOperatorRegisteredInAVS(
                msg.sender, IProposerRegistry.RestakingServiceType.EIGENLAYER_GATEWAY
            )
                && !proposerRegistry.isOperatorRegisteredInAVS(
                    msg.sender, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
                ) && msg.sender != owner()
        ) {
            revert OperatorNotRegistered();
        }
        _;
    }

    // Replace constructor with disable-initializers
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
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
        address _rewardInitiator,
        address _registryCoordinator,
        uint256 _underwriterShareBips,
        address _registry
    )
        public
        virtual
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();

        proposerRegistry = IProposerRegistry(_proposerRegistry);
        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_delegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_strategyManager);
        EIGEN_POD_MANAGER = IEigenPodManager(_eigenPodManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_rewardCoordinator);
        _setRewardsInitiator(_rewardInitiator);
        UNDERWRITER_SHARE_BIPS = _underwriterShareBips;
        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_registryCoordinator);
        REGISTRY = IRegistry(_registry);
    }

    /// @notice Register multiple validators for multiple pod owners in a single
    /// transaction
    /// @param registrations Array of arrays containing validator BLS public keys,
    /// where each inner array corresponds to a
    /// pod owner
    /// @dev Length of valPubKeys array must match length of podOwners array
    function registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress
    )
        external
    {
        _registerValidators(
            registrations, delegationSignatures, delegateePubKey, delegateeAddress
        );
    }

    function _registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress
    )
        internal
    {
        require(
            delegateePubKey.length > 0,
            "ValidatorAVS: Must choose a valid Gateway delegate"
        );

        // Check if operator is registered in Validator Operator Set(1)
        if (!REGISTRY_COORDINATOR.getOperatorSet(1).contains(msg.sender)) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }

        if (!REGISTRY_COORDINATOR.getOperatorSet(0).contains(delegateeAddress)) {
            revert OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
        }

        require(
            registrations.length == delegationSignatures.length,
            "Invalid number of delegation signatures"
        );

        // send 0.11 eth to meet the Registry.MIN_COLLATERAL() requirement
        bytes32 registrationRoot =
            REGISTRY.register{ value: 0.11 ether }(registrations, msg.sender);

        for (uint256 i = 0; i < registrations.length; ++i) {
            operatorToDelegation[msg.sender][registrationRoot][registrations[i].pubkey] =
            ISlasher.SignedDelegation({
                delegation: IRegistry.Delegation({
                    proposer: registrations[i].pubkey,
                    delegate: delegateePubKey,
                    committer: delegateeAddress,
                    slot: type(uint64).max,
                    metadata: bytes("")
                }),
                signature: delegationSignatures[i]
            });
        }
    }

    // Todo: use better data strucutre for the nested map
    // Todo: extend the operator set to be more forward compatible
    function unregisterValidators(bytes32 registrationRoot) external {
        delete operatorToDelegation[msg.sender][registrationRoot];
        REGISTRY.unregister(registrationRoot);
    }

    function createOperatorSet(IStrategy[] memory strategies) external onlyOwner {
        _createOperatorSet(strategies);
    }

    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        _addStrategiesToOperatorSet(operatorSetId, strategies);
    }

    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        _removeStrategiesFromOperatorSet(operatorSetId, strategies);
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

    function createOperatorSet(IStrategy[] memory strategies)
        external
        onlyOwner
        returns (uint32)
    {
        return REGISTRY_COORDINATOR.createOperatorSet(strategies);
    }

    function createAVSRewardsSubmission(
        IRewardsCoordinator.RewardsSubmission[] calldata submissions
    )
        external
    {
        _createAVSRewardsSubmission(submissions);
    }

    function processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        external
    {
        _processClaim(claim, recipient);
    }

    function getOperatorSetCount() public view returns (uint32) {
        return REGISTRY_COORDINATOR.getOperatorSetCount();
    }

    /// @dev Internal function that registers an operator.
    function registerOperatorToAvs(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    )
        internal
    {
        revert UseAllocationManagerForOperatorRegistration();
    }

    // ========= INTERNAL FUNCTIONS =========

    function _createOperatorSet(IStrategy[] memory strategies) internal {
        REGISTRY_COORDINATOR.createOperatorSet(strategies);
    }

    function _addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        REGISTRY_COORDINATOR.addStrategiesToOperatorSet(operatorSetId, strategies);
    }

    function _removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        REGISTRY_COORDINATOR.removeStrategiesFromOperatorSet(operatorSetId, strategies);
    }

    function _createAVSRewardsSubmission(
        IRewardsCoordinator.RewardsSubmission[] calldata submissions
    )
        internal
    {
        revert UseCreateOperatorDirectedAVSRewardsSubmission();
    }

    function _createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions
    )
        internal
    {
        require(
            keccak256(bytes(submissions[0].description))
                == keccak256(bytes("underwriter")),
            "EigenLayerMiddleware: First submission must be the Underwriter portion"
        );

        require(
            keccak256(bytes(submissions[1].description)) == keccak256(bytes("validator")),
            "EigenLayerMiddleware: Second submission must be the Validator portion"
        );

        require(
            submissions[0].startTimestamp == block.timestamp
                && submissions[1].startTimestamp == block.timestamp,
            "EigenLayerMiddleware: Underwriter and Validator submissions must have start timestamp of current block"
        );

        require(
            submissions[0].duration == REWARD_DURATION
                && submissions[1].duration == REWARD_DURATION,
            "EigenLayerMiddleware: Underwriter and Validator submissions must have the same duration"
        );

        // Enforce that the second submission's operator rewards are always zero.
        // The validator portion is determined by _handleUnderwriterSubmission, which
        // calculates how many tokens go to the validator side.
        IRewardsCoordinator.OperatorReward[] memory validatorRewards =
            submissions[1].operatorRewards;
        for (uint256 i = 0; i < validatorRewards.length; i++) {
            require(
                validatorRewards[i].amount == 0,
                "EigenLayerMiddleware: Validator submission reward must be zero"
            );
        }

        // 1) Handle Underwriter portion
        uint256 validatorAmount = _handleUnderwriterSubmission(submissions[0]);

        // 2) Handle Validator portion
        _handleValidatorRewards(submissions[1], validatorAmount);
    }

    function _handleUnderwriterSubmission(
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission calldata submission
    )
        internal
        returns (uint256 validatorAmount)
    {
        // Calculate total underwriter amount
        uint256 totalAmount;
        for (uint256 i = 0; i < submission.operatorRewards.length; i++) {
            totalAmount += submission.operatorRewards[i].amount;
        }

        // Transfer tokens from reward initiator to this contract
        require(
            submission.token.transferFrom(msg.sender, address(this), totalAmount),
            "Underwriter token transfer failed"
        );

        uint256 underwriterAmount =
            Math.mulDiv(totalAmount, UNDERWRITER_SHARE_BIPS, 10_000);
        validatorAmount = totalAmount - underwriterAmount;

        // Get all active underwriter operators registered for Underwriter Operator Set(0)
        address[] memory operators =
            REGISTRY_COORDINATOR.getOperatorSetOperators(uint32(0));
        require(operators.length > 0, "UnderwriterAVS: No operators");

        // Calculate per-operator reward amount - multiply first to avoid precision loss
        uint256 numOperators = operators.length;
        uint256 baseShare = underwriterAmount / numOperators;
        uint256 leftover = underwriterAmount % numOperators;
        require(baseShare > 0, "UnderwriterAVS: Reward per operator is zero");

        // Create array of operator rewards with even distribution
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](numOperators);

        // Assign each operator a baseShare, plus one extra token until leftover is exhausted
        for (uint256 i = 0; i < numOperators; i++) {
            uint256 share = baseShare;
            if (i < leftover) {
                // Give one extra token to the first 'leftover' operators
                share += 1;
            }
            opRewards[i] = IRewardsCoordinatorTypes.OperatorReward({
                operator: operators[i],
                amount: share
            });
        }

        // Todo: Sweep any leftover dust from uneven division to treasury or redistribute

        // Create final submission array with single entry
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory
            underwriterSubmissions =
                new IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[](1);

        // Configure submission with operator rewards and metadata
        underwriterSubmissions[0] = IRewardsCoordinatorTypes
            .OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(
                abi.encodePacked(submission.description, "(Underwriter portion)")
            )
        });

        // Approve RewardsCoordinator to spend the underwriter portion
        submission.token.approve(address(REWARDS_COORDINATOR), underwriterAmount);

        // Submit rewards distribution to coordinator
        REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(
            address(this), underwriterSubmissions
        );
    }

    function _handleValidatorRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 validatorAmount
    )
        internal
    {
        // Get validator operators and total count for this AVS
        address[] memory operators =
            REGISTRY_COORDINATOR.getOperatorSetOperators(uint32(1));
        require(operators.length > 0, "ValidatorAVS: No operators");

        // Todo: add method to query number of validators registered for Validator Operator Set(1)
        uint256 totalValidatorCount =
            proposerRegistry.getTotalValidatorCountForAVS(address(this));
        require(totalValidatorCount > 0, "ValidatorAVS: No validators registered");

        // Build array of OperatorRewards proportionally
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            // Todo: add method to query number of validators registered for an operator
            uint256 opValidatorCount =
                proposerRegistry.getValidatorCountForOperatorInAVS(operators[i]);
            require(opValidatorCount > 0, "ValidatorAVS: Operator has no validators");

            // Share of the total validatorAmount = amount * (opCount/totalCount)
            uint256 share = (validatorAmount * opValidatorCount) / totalValidatorCount;
            require(share > 0, "ValidatorAVS: Operator share is zero");

            opRewards[i] = IRewardsCoordinatorTypes.OperatorReward({
                operator: operators[i],
                amount: share
            });
        }

        // Combine into a single submission
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory
            validatorSubmissions =
                new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);

        validatorSubmissions[0] = IRewardsCoordinatorTypes
            .OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(
                abi.encodePacked(submission.description, " (Validator portion)")
            )
        });

        // Approve RewardsCoordinator to spend the validator portion
        submission.token.approve(address(REWARDS_COORDINATOR), validatorAmount);

        REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(
            address(this), validatorSubmissions
        );
    }

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

    /// @dev Internal function that deregisters an operator.
    function _deregisterOperatorFromAVS(address operator) internal {
        AVS_DIRECTORY.deregisterOperatorFromAVS(operator);
        proposerRegistry.deregisterOperator(operator);
    }

    /// @dev Internal function that processes a claim.
    function _processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        internal
    {
        IRewardsCoordinator(REWARDS_COORDINATOR).processClaim(claim, recipient);
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

    /// @notice Get the AVS Directory contract instance
    function getAVSDirectory() public view returns (IAVSDirectory) {
        return AVS_DIRECTORY;
    }

    /// @notice Get the ProposerRegistry contract instance
    function getProposerRegistry() public view returns (IProposerRegistry) {
        return proposerRegistry;
    }

    /// @notice Get the EigenPodManager contract instance
    function getEigenPodManager() public view returns (IEigenPodManager) {
        return EIGEN_POD_MANAGER;
    }

    /// @notice Get the DelegationManager contract instance
    function getDelegationManager() public view returns (DelegationManagerStorage) {
        return DELEGATION_MANAGER;
    }

    /// @notice Get the StrategyManager contract instance
    function getStrategyManager() public view returns (StrategyManagerStorage) {
        return STRATEGY_MANAGER;
    }

    /// @notice Get the RewardsCoordinator contract instance
    function getRewardsCoordinator() public view returns (IRewardsCoordinator) {
        return REWARDS_COORDINATOR;
    }

    /// @notice Get the rewards initiator address
    function getRewardsInitiator() public view returns (address) {
        return REWARD_INITIATOR;
    }

    /// @notice Get the underwriter share in BIPS
    function getUnderwriterShareBips() public view returns (uint256) {
        return UNDERWRITER_SHARE_BIPS;
    }

    /// @notice Query the stake amount for an operator across all strategies
    /// @param operator The address of the operator to query
    /// @return strategyAddresses Array of strategy addresses
    /// @return stakeAmounts Array of corresponding stake amounts
    function getStrategiesAndStakes(address operator)
        external
        view
        returns (IStrategy[] memory strategies, uint256[] memory stakeAmounts)
    {
        strategies = getOperatorRestakedStrategies(operator);
        stakeAmounts = new uint256[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            stakeAmounts[i] = strategies[i].sharesToUnderlyingView(
                DELEGATION_MANAGER.getOperatorShares(operator, strategies[i])
            );
        }
    }

    /// @notice Query the registration status of an operator
    /// @param operator The address of the operator to query
    /// @return isRegistered True if the operator is registered in EigenLayer
    function verifyRegistration(address operator)
        public
        view
        returns (OperatorSet[] memory)
    {
        // First check if operator is registered in delegation manager
        bool isDelegated = DELEGATION_MANAGER.isOperator(operator);
        if (!isDelegated) {
            revert OperatorNotRegisteredInEigenLayer();
        }

        // Check operator's registration status in this AVS
        OperatorSet[] memory operatorSets =
            REGISTRY_COORDINATOR.getOperatorAllocatedOperatorSets(operator);
        if (operatorSets.length == 0) {
            revert OperatorNotRegisteredInAVS();
        }

        return operatorSets;
    }

    /// @notice Get the strategies an operator has restaked in
    /// @param operator Address of the operator
    /// @return Array of strategy addresses the operator has restaked in
    function getOperatorRestakedStrategies(address operator)
        public
        view
        returns (IStrategy[] memory strategies)
    {
        OperatorSet[] memory operatorSets = verifyRegistration(operator);

        EnumerableSet.AddressSet memory restakedStrategies =
            new EnumerableSet.AddressSet();
        for (uint256 i = 0; i < operatorSets.length; i++) {
            IStrategy[] memory setStrategies = REGISTRY_COORDINATOR
                .getOperatorAllocatedStrategies(operator, operatorSets[i].operatorSetId);
            for (uint256 j = 0; j < setStrategies.length; j++) {
                if (!restakedStrategies.contains(address(setStrategies[j]))) {
                    restakedStrategies.add(address(setStrategies[j]));
                    strategies.push(setStrategies[j]);
                }
            }
        }
    }

    /// @notice Get all strategies that can be restaked across all operator sets
    /// @return Array of all registered strategy addresses
    function getAllRestakeableStrategies()
        external
        view
        returns (EnumerableSet.AddressSet memory)
    {
        uint32 operatorSetCount = REGISTRY_COORDINATOR.getOperatorSetCount();
        EnumerableSet.AddressSet memory strategies = new EnumerableSet.AddressSet();
        for (uint32 i = 0; i < operatorSetCount; i++) {
            IStrategy[] memory operatorSet =
                REGISTRY_COORDINATOR.getOperatorSetStrategies(i);
            for (uint256 j = 0; j < operatorSet.length; j++) {
                strategies.add(address(operatorSet[j]));
            }
        }
        return strategies;
    }

    /// @notice Get all strategies for a given operator set
    /// @param operatorSetId The ID of the operator set
    /// @return Array of all strategies in the operator set
    function getRestakeableOperatorSetStrategies(uint32 operatorSetId)
        external
        view
        returns (IStrategy[] memory)
    {
        require(
            operatorSetId <= REGISTRY_COORDINATOR.getOperatorSetCount(),
            "Operator set not found"
        );
        return REGISTRY_COORDINATOR.getOperatorSetStrategies(operatorSetId);
    }

    /// @notice Gets the ValidatorAVS address from the registry by AVS type
    /// @return The address of the ValidatorAVS contract
    function getValidatorAVSAddress() public view returns (address) {
        return address(proposerRegistry.validatorAVS());
    }

    /// @notice Gets the ValidatorAVS contract instance from the registry
    /// @return The ValidatorAVS contract instance
    function getValidatorAVS() public view returns (IValidatorAVS) {
        return IValidatorAVS(proposerRegistry.validatorAVS());
    }
}
