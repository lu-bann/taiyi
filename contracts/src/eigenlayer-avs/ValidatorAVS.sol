// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EigenLayerMiddleware } from "../abstract/EigenLayerMiddleware.sol";

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
        bytes delegatedGatewayPubKey,
        bytes validatorPubKey
    );

    // ========= ERRORS =========
    error SenderNotPodOwnerOrOperator();
    error OperatorIsNotYetRegisteredInTaiyiProposerRegistry();
    error OperatorIsNotYetRegisteredInTaiyiGatewayAVS();
    error UseGatewayAVSForRewards(address gatewayAVS);

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

    /// @notice Modifier that restricts function access to only the gateway AVS contract
    /// @dev Reverts if msg.sender is not the gateway AVS contract address
    modifier onlyGatewayAVS() {
        require(
            msg.sender == getGatewayAVSAddress(),
            "ValidatorAVS: caller is not gateway AVS"
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
        uint256 _gatewayShareBips
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
            _gatewayShareBips
        );
    }

    /// @notice Override of createOperatorDirectedAVSRewardsSubmission that redirects to GatewayAVS
    /// @dev This function always reverts and directs users to use GatewayAVS for reward distribution
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
    )
        public
        view
        override
    {
        revert UseGatewayAVSForRewards(super.getGatewayAVSAddress());
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
            operator, IProposerRegistry.AVSType.VALIDATOR, bytes("")
        );
    }

    /// @notice Internal function to register multiple validators for a pod owner or regular validators
    /// @dev Has two paths:
    ///      1. For EigenPod validators (when called by pod owner or delegated operator):
    ///         - Gateway public key must be non-empty
    ///         - Operator must be registered in Validator AVS
    ///         - Pod owner must have active EigenPod
    ///         - Validators must be active in EigenLayer
    ///      2. For regular validators (when called by registered operator):
    ///         - Gateway public key must be non-empty
    ///         - Caller must be registered in Validator AVS
    ///         - No EigenPod checks required
    ///         - Currently no BLS signature verification (will be added when Petra is live)
    ///
    /// @param valPubKeys Array of validator BLS public keys to register
    /// @param podOwner Address of the EigenPod owner (if address(0), registers as regular validator)
    /// @param delegatedGatewayPubKey The delegated gateway public key (cannot be empty)
    function _registerValidators(
        bytes[] calldata valPubKeys,
        address podOwner,
        bytes calldata delegatedGatewayPubKey
    )
        internal
        override
    {
        require(
            delegatedGatewayPubKey.length > 0,
            "ValidatorAVS: Must choose a valid Gateway delegate"
        );

        // Verify the delegated gateway belongs to a registered gateway operator
        _validateGatewayDelegatee(delegatedGatewayPubKey);

        // Check if caller is a registered operator in ValidatorAVS
        bool isRegisteredOperator = proposerRegistry.isOperatorRegisteredInAVS(
            msg.sender, IProposerRegistry.AVSType.VALIDATOR
        );

        if (podOwner != address(0)) {
            // Path 1: EigenPod validator registration
            _registerEigenPodValidators(
                valPubKeys, podOwner, delegatedGatewayPubKey, isRegisteredOperator
            );
        } else {
            // Path 2: Regular validator registration
            _registerRegularValidators(
                valPubKeys, delegatedGatewayPubKey, isRegisteredOperator
            );
        }
    }

    /// @dev Validates that the delegated gateway public key belongs to a registered gateway operator
    /// @param delegatedGatewayPubKey The gateway public key to validate
    function _validateGatewayDelegatee(bytes calldata delegatedGatewayPubKey)
        internal
        view
    {
        // Cache the delegated key hash to avoid computing it multiple times
        bytes32 delegatedKeyHash = keccak256(delegatedGatewayPubKey);

        // Get all gateway operators
        address[] memory gatewayOperators =
            proposerRegistry.getActiveOperatorsForAVS(getGatewayAVSAddress());

        bool isValidGatewayDelegatee = false;
        for (uint256 i = 0; i < gatewayOperators.length; i++) {
            (bytes memory operatorGatewayPubKey, bool isActive) = proposerRegistry
                .operatorInfo(gatewayOperators[i], IProposerRegistry.AVSType.GATEWAY);

            // Check key hash first as it's cheaper than checking isActive
            if (keccak256(operatorGatewayPubKey) == delegatedKeyHash && isActive) {
                isValidGatewayDelegatee = true;
                break;
            }
        }

        require(
            isValidGatewayDelegatee,
            "ValidatorAVS: Delegated gateway must be a registered gateway operator"
        );
    }

    /// @dev Registers validators that are part of EigenLayer through EigenPod
    function _registerEigenPodValidators(
        bytes[] calldata valPubKeys,
        address podOwner,
        bytes calldata delegatedGatewayPubKey,
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

        address operator = getDelegationManager().delegatedTo(podOwner);

        // Validate operator registration
        if (
            !getProposerRegistry().isOperatorRegisteredInAVS(
                operator, IProposerRegistry.AVSType.VALIDATOR
            )
        ) {
            revert OperatorIsNotYetRegisteredInTaiyiProposerRegistry();
        }

        // Verify pod and register validators
        require(getEigenPodManager().hasPod(podOwner), "No Pod exists");
        IEigenPod pod = getEigenPodManager().getPod(podOwner);

        for (uint256 i = 0; i < valPubKeys.length; ++i) {
            if (
                pod.validatorPubkeyToInfo(valPubKeys[i]).status
                    != IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
            ) {
                revert ValidatorNotActiveWithinEigenCore();
            }

            proposerRegistry.registerValidator(
                valPubKeys[i], operator, delegatedGatewayPubKey
            );

            emit ValidatorOperatorRegistered(
                operator, address(this), delegatedGatewayPubKey, valPubKeys[i]
            );
        }
    }

    /// @dev Registers regular validators that are not part of EigenLayer
    function _registerRegularValidators(
        bytes[] calldata valPubKeys,
        bytes calldata delegatedGatewayPubKey,
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
                delegatedGatewayPubKey
            );

            emit ValidatorOperatorRegistered(
                msg.sender, address(this), delegatedGatewayPubKey, valPubKeys[i]
            );
        }
    }

    /// @notice Handles validator-based reward distribution logic.
    /// @dev Can only be invoked by the gateway AVS during reward distribution.
    ///      Distributes reward among operators proportional to their validator count in this AVS.
    /// @param submission The operator-directed reward submission info.
    /// @param validatorAmount The total portion allocated to validators.
    function handleValidatorRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 validatorAmount
    )
        external
        onlyGatewayAVS
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
            proposerRegistry.isOperatorRegisteredInAVS(
                msg.sender, IProposerRegistry.AVSType.VALIDATOR
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
            proposerRegistry.isOperatorRegisteredInAVS(
                msg.sender, IProposerRegistry.AVSType.VALIDATOR
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
