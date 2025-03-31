// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
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

import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";

import { BLS } from "@urc/lib/BLS.sol";

/// @title EigenLayer Middleware contract
/// @notice This contract is used to manage the registration of operators in EigenLayer core
contract EigenLayerMiddleware is
    OwnableUpgradeable,
    UUPSUpgradeable,
    EigenLayerMiddlewareStorage
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    // ========= MODIFIERS =========

    /// @notice Modifier that restricts function access to operators registered
    /// in EigenLayer core
    /// @dev Reverts with CallerNotOperator if msg.sender is not an EigenLayer
    /// operator
    modifier onlyValidatorOperatorSet() {
        if (
            REGISTRY_COORDINATOR.getOperatorFromOperatorSet(uint32(1), msg.sender)
                == address(0)
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        _;
    }

    /// @notice when applied to a function, only allows the RegistryCoordinator to call it
    modifier onlyRegistryCoordinator() {
        if (msg.sender != address(REGISTRY_COORDINATOR)) {
            revert OnlyRegistryCoordinator();
        }
        _;
    }

    /// @notice only rewardsInitiator can call createAVSRewardsSubmission
    modifier onlyRewardsInitiator() {
        if (msg.sender != REWARD_INITIATOR) {
            revert OnlyRewardsInitiator();
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
    /// @param _avsDirectory Address of AVS directory contract
    /// @param _delegationManager Address of delegation manager contract
    /// @param _rewardCoordinator Address of reward coordinator contract
    /// @param _rewardInitiator Address of reward initiator
    function initialize(
        address _owner,
        address _avsDirectory,
        address _delegationManager,
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

        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_delegationManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_rewardCoordinator);
        _setRewardsInitiator(_rewardInitiator);
        UNDERWRITER_SHARE_BIPS = _underwriterShareBips;
        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_registryCoordinator);
        REGISTRY = Registry(_registry);
    }

    // Todo: add a slashing function in ISlasher to slash the operator when Registry.slashRegistration is successfully
    //       should also use FRAUD_PROOF_PERIOD() to maintain the slashable period
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
        address delegateeAddress,
        bytes[] calldata data
    )
        external
    {
        _registerValidators(
            registrations, delegationSignatures, delegateePubKey, delegateeAddress, data
        );
    }

    /// @notice Batch set delegations for a registration root
    /// @param registrationRoot The registration root
    /// @param pubkeys Array of validator pubkeys
    /// @param delegations Array of signed delegations
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external
    {
        _batchSetDelegations(registrationRoot, pubkeys, delegations);
    }

    function unregisterValidators(bytes32 registrationRoot) external {
        // Ensure the registration root is valid for this operator
        if (
            registrationRoot == bytes32(0)
                || operatorDelegations[msg.sender][registrationRoot].delegationMap.length()
                    == 0
        ) {
            revert OperatorNotRegistered();
        }

        // Get reference to the delegation store
        DelegationStore storage delegationStore =
            operatorDelegations[msg.sender][registrationRoot];

        // Clear all delegations
        for (uint256 i = 0; i < delegationStore.delegationMap.length(); i++) {
            (uint256 index, bytes32 pubkeyHash) = delegationStore.delegationMap.at(i);
            delete delegationStore.delegations[pubkeyHash];
            delegationStore.delegationMap.remove(index);
        }

        // Delete the pubkey hashes array
        delete operatorDelegations[msg.sender][registrationRoot];
        operatorRegistrationRoots[msg.sender].remove(registrationRoot);

        // Unregister from the registry
        REGISTRY.unregister(registrationRoot);
    }

    function createOperatorSet(IStrategy[] memory strategies)
        external
        onlyOwner
        returns (uint32)
    {
        return REGISTRY_COORDINATOR.createOperatorSet(strategies);
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

    /// @dev Internal function that registers an operator.
    function _registerOperatorToAvs(
        address, /* operator */
        ISignatureUtils.SignatureWithSaltAndExpiry calldata /* operatorSignature */
    )
        internal
    {
        revert UseAllocationManagerForOperatorRegistration();
    }

    // ========= INTERNAL FUNCTIONS =========

    function _batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        internal
        onlyValidatorOperatorSet
    {
        (address owner,,, uint32 registeredAt, uint32 unregisteredAt, uint32 slashedAt) =
            REGISTRY.registrations(registrationRoot);
        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != msg.sender) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        if (slashedAt != 0) {
            revert OperatorSlashed();
        }

        if (unregisteredAt < block.number) {
            revert OperatorUnregistered();
        }

        if (registeredAt + REGISTRY.FRAUD_PROOF_WINDOW() > block.number) {
            revert OperatorFraudProofPeriodNotOver();
        }

        DelegationStore storage delegationStore =
            operatorDelegations[msg.sender][registrationRoot];
        require(pubkeys.length == delegations.length, "Array length mismatch");
        require(
            delegationStore.delegationMap.length() == pubkeys.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < pubkeys.length; i++) {
            bytes32 pubkeyHash = keccak256(abi.encode(pubkeys[i]));

            (, bytes32 storedHash) = delegationStore.delegationMap.at(i);
            if (storedHash == pubkeyHash) {
                delegationStore.delegations[pubkeyHash] = delegations[i];
            }
        }
    }

    function _registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        internal
        onlyValidatorOperatorSet
    {
        if (
            REGISTRY_COORDINATOR.getOperatorFromOperatorSet(0, delegateeAddress)
                == address(0)
        ) {
            revert OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
        }

        require(
            registrations.length == delegationSignatures.length,
            "Invalid number of delegation signatures"
        );

        // send 0.11 eth to meet the Registry.MIN_COLLATERAL() requirement
        bytes32 registrationRoot =
            REGISTRY.register{ value: 0.11 ether }(registrations, msg.sender);

        DelegationStore storage delegationStore =
            operatorDelegations[msg.sender][registrationRoot];

        operatorRegistrationRoots[msg.sender].add(registrationRoot);

        for (uint256 i = 0; i < registrations.length; ++i) {
            ISlasher.SignedDelegation memory signedDelegation = ISlasher.SignedDelegation({
                delegation: ISlasher.Delegation({
                    proposer: registrations[i].pubkey,
                    delegate: delegateePubKey,
                    committer: delegateeAddress,
                    slot: type(uint64).max,
                    metadata: data[i]
                }),
                signature: delegationSignatures[i]
            });

            bytes32 pubkeyHash = keccak256(abi.encode(registrations[i].pubkey));

            delegationStore.delegations[pubkeyHash] = signedDelegation;
            delegationStore.delegationMap.set(i, pubkeyHash); // Use index as value for enumeration
        }
    }

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
        IRewardsCoordinator.RewardsSubmission[] calldata /* submissions */
    )
        internal
    {
        revert UseCreateOperatorDirectedAVSRewardsSubmission();
    }

    function _createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions
    )
        internal
        onlyRewardsInitiator
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

        uint256 totalValidatorCount = 0;
        for (uint256 i = 0; i < operators.length; i++) {
            uint256 opRegistrationRootCount =
                operatorRegistrationRoots[operators[i]].length();
            for (uint256 j = 0; j < opRegistrationRootCount; j++) {
                bytes32 registrationRoot = operatorRegistrationRoots[operators[i]].at(j);
                totalValidatorCount += operatorDelegations[operators[i]][registrationRoot]
                    .delegationMap
                    .length();
            }
        }

        require(totalValidatorCount > 0, "ValidatorAVS: No validators registered");

        // Build array of OperatorRewards proportionally
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            uint256 opValidatorCount = 0;
            uint256 opRegistrationRootCount =
                operatorRegistrationRoots[operators[i]].length();
            for (uint256 j = 0; j < opRegistrationRootCount; j++) {
                bytes32 registrationRoot = operatorRegistrationRoots[operators[i]].at(j);
                opValidatorCount += operatorDelegations[operators[i]][registrationRoot]
                    .delegationMap
                    .length();
            }
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

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    function _setRewardsInitiator(address newRewardsInitiator) internal {
        REWARD_INITIATOR = newRewardsInitiator;
        emit RewardsInitiatorUpdated(REWARD_INITIATOR, newRewardsInitiator);
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

    /// @notice Query the stake amount for an operator across all strategies
    /// @param operator The address of the operator to query
    /// @return strategies Array of strategy addresses
    /// @return stakeAmounts Array of corresponding stake amounts
    function getStrategiesAndStakes(address operator)
        external
        view
        returns (IStrategy[] memory strategies, uint256[] memory stakeAmounts)
    {
        strategies = getOperatorRestakedStrategies(operator);
        stakeAmounts = DELEGATION_MANAGER.getOperatorShares(operator, strategies);
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
    /// @return strategies Array of strategy addresses the operator has restaked in
    function getOperatorRestakedStrategies(address operator)
        public
        view
        returns (IStrategy[] memory strategies)
    {
        OperatorSet[] memory operatorSets = verifyRegistration(operator);

        // First count all strategies across all operator sets
        uint256 totalStrategiesCount = 0;
        for (uint256 i = 0; i < operatorSets.length; i++) {
            IStrategy[] memory setStrategies = REGISTRY_COORDINATOR
                .getOperatorAllocatedStrategies(operator, operatorSets[i].id);
            totalStrategiesCount += setStrategies.length;
        }

        // Create array to store all strategies (with potential duplicates)
        address[] memory allStrategies = new address[](totalStrategiesCount);
        uint256 allStrategiesLength = 0;

        // Fill array with all strategies
        for (uint256 i = 0; i < operatorSets.length; i++) {
            IStrategy[] memory setStrategies = REGISTRY_COORDINATOR
                .getOperatorAllocatedStrategies(operator, operatorSets[i].id);
            for (uint256 j = 0; j < setStrategies.length; j++) {
                allStrategies[allStrategiesLength] = address(setStrategies[j]);
                allStrategiesLength++;
            }
        }

        // Count unique strategies
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < i; j++) {
                if (allStrategies[j] == allStrategies[i]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                uniqueCount++;
            }
        }

        // Create result array with unique strategies
        strategies = new IStrategy[](uniqueCount);
        uint256 resultIndex = 0;

        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < resultIndex; j++) {
                if (allStrategies[i] == address(strategies[j])) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                strategies[resultIndex] = IStrategy(allStrategies[i]);
                resultIndex++;
            }
        }
    }

    /// @notice Get all strategies that can be restaked across all operator sets
    /// @return Array of all registered strategy addresses
    function getAllRestakeableStrategies() external view returns (address[] memory) {
        uint32 operatorSetCount = REGISTRY_COORDINATOR.getOperatorSetCount();

        // First count all strategies across all operator sets
        uint256 totalStrategiesCount = 0;
        for (uint32 i = 0; i < operatorSetCount; i++) {
            IStrategy[] memory operatorSet =
                REGISTRY_COORDINATOR.getOperatorSetStrategies(i);
            totalStrategiesCount += operatorSet.length;
        }

        // Create array to store all strategies (with potential duplicates)
        address[] memory allStrategies = new address[](totalStrategiesCount);
        uint256 allStrategiesLength = 0;

        // Fill array with all strategies
        for (uint32 i = 0; i < operatorSetCount; i++) {
            IStrategy[] memory operatorSet =
                REGISTRY_COORDINATOR.getOperatorSetStrategies(i);
            for (uint256 j = 0; j < operatorSet.length; j++) {
                allStrategies[allStrategiesLength] = address(operatorSet[j]);
                allStrategiesLength++;
            }
        }

        // Count unique strategies
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < i; j++) {
                if (allStrategies[j] == allStrategies[i]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                uniqueCount++;
            }
        }

        // Create result array with unique strategies
        address[] memory result = new address[](uniqueCount);
        uint256 resultIndex = 0;

        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < resultIndex; j++) {
                if (allStrategies[i] == result[j]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                result[resultIndex] = allStrategies[i];
                resultIndex++;
            }
        }

        // Create correctly sized result array
        address[] memory strategies = new address[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; i++) {
            strategies[i] = result[i];
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

    /// @notice Gets a delegation for an operator by validator pubkey
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @param pubkey The validator pubkey
    /// @return The signed delegation
    function getDelegation(
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        public
        view
        returns (ISlasher.SignedDelegation memory)
    {
        (address owner,,, uint32 registeredAt,,) =
            REGISTRY.registrations(registrationRoot);

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        bytes32 pubkeyHash = keccak256(abi.encode(pubkey));
        DelegationStore storage delegationStore =
            operatorDelegations[operator][registrationRoot];

        if (delegationStore.delegations[pubkeyHash].delegation.committer != address(0)) {
            return delegationStore.delegations[pubkeyHash];
        } else {
            revert PubKeyNotFound();
        }
    }

    /// @notice Gets all delegations for an operator
    /// @param operator The operator address
    /// @param registrationRoot The registration root (optional, if not specified uses active root)
    /// @return pubkeys Array of validator pubkeys
    /// @return delegations Array of signed delegations
    function getAllDelegations(
        address operator,
        bytes32 registrationRoot
    )
        public
        view
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        )
    {
        (address owner,,, uint32 registeredAt,,) =
            REGISTRY.registrations(registrationRoot);

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        DelegationStore storage delegationStore =
            operatorDelegations[operator][registrationRoot];
        uint256 count = delegationStore.delegationMap.length();

        pubkeys = new BLS.G1Point[](count);
        delegations = new ISlasher.SignedDelegation[](count);

        for (uint256 i = 0; i < count; i++) {
            bytes32 pubkeyHash = delegationStore.delegationMap.get(i);
            ISlasher.SignedDelegation memory delegation =
                delegationStore.delegations[pubkeyHash];
            pubkeys[i] = delegation.delegation.proposer;
            delegations[i] = delegation;
        }
    }

    function getOperatorSetCount() public view returns (uint32) {
        return REGISTRY_COORDINATOR.getOperatorSetCount();
    }
}
