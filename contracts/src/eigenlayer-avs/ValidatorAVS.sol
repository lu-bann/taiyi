// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EigenLayerMiddleware } from "./EigenLayerMiddleware.sol";

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IEigenPod } from "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IEigenPodTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

/// @title ValidatorAVS
/// @notice A standalone AVS for validator distribution. Receives a
///         validator-portion from the EigenLayerMiddleware
///         and splits it by operator validator counts.
contract ValidatorAVS is EigenLayerMiddleware {
    // ========= EVENTS =========
    event ValidatorOperatorRegistered(
        address indexed operator,
        address indexed avs,
        bytes delegatedUnderwriterPubKey,
        bytes validatorPubKey
    );

    // ========= ERRORS =========
    error SenderNotPodOwnerOrOperator();
    error OperatorIsNotYetRegisteredInTaiyiProposerRegistry();
    error OperatorIsNotYetRegisteredInTaiyiUnderwriterAVS();
    error UseUnderwriterAVSForRewards(address underwriterAVS);

    // ========= MODIFIER =========
    /// @notice Modifier that restricts function access to either the pod owner or their delegated operator
    /// @dev Reverts with SenderNotPodOwnerOrOperator if msg.sender is neither the pod owner nor their delegated operator
    modifier onlyPodOwnerOrOperator(address podOwner) {
        if (
            msg.sender != podOwner
                && msg.sender != getDelegationManager().delegatedTo(podOwner)
        ) {
            revert SenderNotPodOwnerOrOperator();
        }
        _;
    }

    /// @notice Modifier that restricts function access to only the underwriter AVS contract
    /// @dev Reverts if msg.sender is not the underwriter AVS contract address
    modifier onlyUnderwriterAVS() {
        require(
            msg.sender == getUnderwriterAVSAddress(),
            "ValidatorAVS: caller is not underwriter AVS"
        );
        _;
    }

    // ========= OVERRIDE FUNCTIONS =========

    function initialize(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator,
        uint256 _underwriterShareBips
    )
        public
        override
        initializer
    {
        // Delegates initialization to the parent contract.
        super.initialize(
            _owner,
            _proposerRegistry,
            _avsDirectory,
            _delegationManager,
            _strategyManager,
            _eigenPodManager,
            _rewardCoordinator,
            _rewardInitiator,
            _underwriterShareBips
        );
    }

    /// @notice Override of createOperatorDirectedAVSRewardsSubmission that redirects to UnderwriterAVS
    /// @dev This function always reverts and directs users to use UnderwriterAVS for reward distribution
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
    )
        public
        view
        override
    {
        revert UseUnderwriterAVSForRewards(super.getUnderwriterAVSAddress());
    }

    /// @dev Internal function that registers an operator.
    function _registerOperatorToAvs(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    )
        internal
        override
        onlyEigenCoreOperator
    {
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
        proposerRegistry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR,
            bytes("")
        );
    }

    /// @notice Internal function to register multiple validators for a pod owner
    /// @dev Enforces several conditions before registering validators:
    ///      1. Underwriter public key must be non-empty (meaning an actual delegate is chosen).
    ///      2. The operator delegated by the EigenPod owner must already be registered:
    ///         - in the Underwriter AVS Directory (primary restaking AVS).
    ///         - in the TaiyiProposerRegistry with the correct AVSType.
    ///      3. The pod owner must have an active EigenPod (already created).
    ///      4. Each validator BLS public key must already be active within EigenLayer.
    ///
    ///      This function also covers the "self-delegation" scenario, where the pod owner
    ///      acts as its own UnderwriterAVS operator.
    ///
    ///      For each validator registered, the contract emits a ValidatorOperatorRegistered event.
    ///      Off-chain, a service in Commit-boost listens to this event, and uses the information
    ///      to send delegation messages to the Relay, adhering to the preconf constraint API found at:
    ///      https://github.com/ethereum-commitments/constraints-specs/blob/main/specs/preconf-api.md#endpoint-constraintsv0builderdelegate
    ///
    ///      Below is the schema referenced for the off-chain delegation:
    ///
    ///      # A signed delegation
    ///      class SignedDelegation(Container):
    ///          message: Delegation
    ///          signature: BLSSignature
    ///
    ///      # A delegation from a proposer to a BLS public key
    ///      class Delegation(Container):
    ///          proposer: BLSPubkey
    ///          delegate: BLSPubkey
    ///          slasher: Address
    ///          valid_until: Slot
    ///          metadata: Bytes
    ///
    /// @param valPubKeys Array of validator BLS public keys to register
    /// @param podOwner Address of the EigenPod owner
    /// @param delegatedUnderwriterPubKey The delegated underwriter public key (cannot be empty)
    function _registerValidators(
        bytes[] calldata valPubKeys,
        address podOwner,
        bytes calldata delegatedUnderwriterPubKey
    )
        internal
        override
    {
        require(
            delegatedUnderwriterPubKey.length > 0,
            "ValidatorAVS: Must choose a valid Underwriter delegate"
        );

        // Verify the delegated underwriter belongs to a registered underwriter operator
        _validateUnderwriterDelegatee(delegatedUnderwriterPubKey);

        // Check if caller is a registered operator in ValidatorAVS
        bool isRegisteredOperator = proposerRegistry.isOperatorRegisteredInAVS(
            msg.sender, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
        );

        if (podOwner != address(0)) {
            // Path 1: EigenPod validator registration
            _registerEigenPodValidators(
                valPubKeys, podOwner, delegatedUnderwriterPubKey, isRegisteredOperator
            );
        } else {
            // Path 2: Regular validator registration
            _registerRegularValidators(
                valPubKeys, delegatedUnderwriterPubKey, isRegisteredOperator
            );
        }
    }

    /// @dev Validates that the delegated underwriter public key belongs to a registered underwriter operator
    /// @param delegatedUnderwriterPubKey The underwriter public key to validate
    function _validateUnderwriterDelegatee(bytes calldata delegatedUnderwriterPubKey)
        internal
        view
    {
        // Cache the delegated key hash to avoid computing it multiple times
        bytes32 delegatedKeyHash = keccak256(delegatedUnderwriterPubKey);

        // Get all underwriter operators
        address[] memory underwriterOperators =
            proposerRegistry.getActiveOperatorsForAVS(getUnderwriterAVSAddress());

        bool isValidUnderwriterDelegatee = false;
        for (uint256 i = 0; i < underwriterOperators.length; i++) {
            (bytes memory operatorUnderwriterPubKey, bool isActive) = proposerRegistry
                .operatorInfo(
                underwriterOperators[i],
                IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            );

            // Check key hash first as it's cheaper than checking isActive
            if (keccak256(operatorUnderwriterPubKey) == delegatedKeyHash && isActive) {
                isValidUnderwriterDelegatee = true;
                break;
            }
        }

        require(
            isValidUnderwriterDelegatee,
            "ValidatorAVS: Delegated underwriter must be a registered underwriter operator"
        );
    }

    function _registerEigenPodValidators(
        bytes[] calldata valPubKeys,
        address podOwner,
        bytes calldata delegatedUnderwriterPubKey,
        bool isRegisteredOperator
    )
        internal
    {
        // Check caller permissions
        bool isPodOwner = msg.sender == podOwner;
        bool isDelegatedOperator =
            msg.sender == getDelegationManager().delegatedTo(podOwner);

        require(
            isPodOwner || isDelegatedOperator || isRegisteredOperator,
            "Caller must be pod owner, delegated operator, or registered operator"
        );

        // Get the operator delegated to by the pod owner.
        // EigenPod owner could be self-delegated
        address operator = getDelegationManager().delegatedTo(podOwner);

        // Check if operator is registered in proposer registry
        if (
            !getProposerRegistry().isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            )
        ) {
            revert OperatorIsNotYetRegisteredInTaiyiProposerRegistry();
        }

        // Check if operator is registered with the underwriter AVS
        if (
            !getProposerRegistry().isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            )
        ) {
            revert OperatorIsNotYetRegisteredInTaiyiUnderwriterAVS();
        }

        // Verify pod owner has an EigenPod
        require(getEigenPodManager().hasPod(podOwner), "No Pod exists");
        IEigenPod pod = getEigenPodManager().getPod(podOwner);

        // Register each validator if they are active in EigenLayer
        uint256 len = valPubKeys.length;
        for (uint256 i = 0; i < len; ++i) {
            // Check validator is active in EigenLayer core
            if (
                pod.validatorPubkeyToInfo(valPubKeys[i]).status
                    != IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
            ) {
                revert ValidatorNotActiveWithinEigenCore();
            }

            // Register validator in proposer registry with delegatedUnderwriterPubKey as delegatee
            proposerRegistry.registerValidator(
                valPubKeys[i], operator, delegatedUnderwriterPubKey
            );

            // Emit event to track validator registration
            emit ValidatorOperatorRegistered(
                operator, address(this), delegatedUnderwriterPubKey, valPubKeys[i]
            );
        }
    }

    /// @dev Registers regular validators that are not part of EigenLayer
    function _registerRegularValidators(
        bytes[] calldata valPubKeys,
        bytes calldata delegatedUnderwriterPubKey,
        bool isRegisteredOperator
    )
        internal
    {
        // Only registered operators can register regular validators
        require(
            isRegisteredOperator,
            "Only registered operators can register regular validators"
        );

        for (uint256 i = 0; i < valPubKeys.length; ++i) {
            proposerRegistry.registerValidator(
                valPubKeys[i],
                msg.sender, // operator is the caller
                delegatedUnderwriterPubKey
            );

            emit ValidatorOperatorRegistered(
                msg.sender, address(this), delegatedUnderwriterPubKey, valPubKeys[i]
            );
        }
    }

    /// @notice Handles validator-based reward distribution logic.
    /// @dev Can only be invoked by the underwriter AVS during reward distribution.
    ///      Distributes reward among operators proportional to their validator count in this AVS.
    /// @param submission The operator-directed reward submission info.
    /// @param validatorAmount The total portion allocated to validators.
    function handleValidatorRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 validatorAmount
    )
        external
        onlyUnderwriterAVS
    {
        // Get validator operators and total count for this AVS
        address[] memory operators =
            proposerRegistry.getActiveOperatorsForAVS(address(this));
        require(operators.length > 0, "ValidatorAVS: No operators");

        uint256 totalValidatorCount =
            proposerRegistry.getTotalValidatorCountForAVS(address(this));
        require(totalValidatorCount > 0, "ValidatorAVS: No validators registered");

        // Build array of OperatorRewards proportionally
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
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

    /// @notice Initiates the opt-out process for a validator
    /// @param pubkey The BLS public key of the validator to opt out
    /// @param signatureExpiry The expiry timestamp for the opt-out signature
    function initiateValidatorOptOut(bytes32 pubkey, uint256 signatureExpiry) external {
        // Check if caller is a registered operator
        require(
            getProposerRegistry().isOperatorRegisteredInAVS(
                msg.sender, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            ),
            "Not a registered operator"
        );

        // Call the registry to initiate opt-out
        proposerRegistry.initOptOut(pubkey, signatureExpiry);
    }

    /// @notice Confirms the opt-out process for a validator after cooldown
    /// @param pubkey The BLS public key of the validator to confirm opt-out
    function confirmValidatorOptOut(bytes32 pubkey) external {
        proposerRegistry.confirmOptOut(pubkey);
    }

    /// @notice Batch initiates opt-out for multiple validators
    /// @param pubkeys Array of BLS public keys of validators to opt out
    /// @param signatureExpiry The expiry timestamp for the opt-out signatures
    function batchInitiateValidatorOptOut(
        bytes32[] calldata pubkeys,
        uint256 signatureExpiry
    )
        external
    {
        // Check if caller is a registered operator
        require(
            getProposerRegistry().isOperatorRegisteredInAVS(
                msg.sender, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            ),
            "Not a registered operator"
        );

        for (uint256 i = 0; i < pubkeys.length; i++) {
            proposerRegistry.initOptOut(pubkeys[i], signatureExpiry);
        }
    }

    /// @notice Batch confirms opt-out for multiple validators after cooldown
    /// @param pubkeys Array of BLS public keys of validators to confirm opt-out
    function batchConfirmValidatorOptOut(bytes32[] calldata pubkeys) external {
        for (uint256 i = 0; i < pubkeys.length; i++) {
            proposerRegistry.confirmOptOut(pubkeys[i]);
        }
    }
}
