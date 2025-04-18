// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EigenLayerMiddleware } from "./EigenLayerMiddleware.sol";

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";

import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title UnderwriterAVS
/// @notice Manages underwriter-specific AVS functionality and reward distribution.
/// @dev Inherits from the abstract EigenLayerMiddleware.
contract UnderwriterAVS is EigenLayerMiddleware {
    error UseRegisterOperatorToAVSWithPubKey();

    event ValidatorAmountForwarded(uint256 validatorAmount);

    /// @notice Restricts function access to only this contract as tx.origin
    modifier onlyThisContractAsTxOrigin() {
        require(tx.origin == address(this), "Only this contract can be tx.origin");
        _;
    }

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

    /// @notice Special registration function for operators to register with UnderwriterAVS
    /// @dev This is the only way for operators to register with UnderwriterAVS since it requires BLS key
    /// @dev The original registerOperatorToAVS function in IServiceManager interface cannot accept BLS
    ///      key as part of registration, so we provide this function to allow BLS key registration alongside
    ///      AVS registration
    /// @param operator The address of the operator to register
    /// @param operatorSignature The operator's signature for AVS registration
    /// @param operatorBLSPubKey The operator's BLS public key
    function registerOperatorToAVSWithPubKey(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature,
        bytes calldata operatorBLSPubKey
    )
        external
        onlyEigenCoreOperator
    {
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
        proposerRegistry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            operatorBLSPubKey
        );
    }

    /// @notice This function is required by IServiceManager but should not be used.
    /// Users must call registerOperatorToAVSWithBLS instead to provide BLS key.
    function registerOperatorToAVS(
        address,
        ISignatureUtils.SignatureWithSaltAndExpiry memory
    )
        external
        pure
        override
    {
        revert UseRegisterOperatorToAVSWithPubKey();
    }

    /// @notice Processes operator rewards for both Underwriter and Validator AVS components
    /// @dev Expects exactly 2 submissions in a specific order - Underwriter first, then Validator
    /// @dev Rewards for Validator AVS will be empty since we handle the distribution in _handleUnderwriterSubmission in this contract
    /// @dev Each submission contains operator addresses and their corresponding reward amounts
    /// @param submissions Array containing reward submissions for Underwriter and Validator
    // Todo: for operators who self delegate into UnderwriterAVS, we need to handle the case where for reward distribution where the fee earned won't be distributred to the validator avs
    function _createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions
    )
        internal
        override
        onlyRewardsInitiator
    {
        // Validate submission count
        require(
            submissions.length == 2,
            "EigenLayerMiddleware: Must pass exactly 2 submissions"
        );

        // Validate Underwriter submission is first
        require(
            keccak256(bytes(submissions[0].description))
                == keccak256(bytes("underwriter")),
            "EigenLayerMiddleware: First submission must be the Underwriter portion"
        );
        // Validate Validator submission is second
        require(
            keccak256(bytes(submissions[1].description)) == keccak256(bytes("validator")),
            "EigenLayerMiddleware: Second submission must be the Validator portion"
        );

        // Enforce that the second submission's operator rewards are always zero.
        // The validator portion is determined by _handleUnderwriterSubmission, which
        // calculates how many tokens go to the validator side.
        IRewardsCoordinator.OperatorReward[] memory validatorRewards =
            submissions[1].operatorRewards;
        for (uint256 i = 0; i < validatorRewards.length; i++) {
            require(
                validatorRewards[i].amount == 0,
                "UnderwriterAVS: Validator submission reward must be zero"
            );
        }

        // 1) Handle Underwriter portion
        uint256 validatorAmount = _handleUnderwriterSubmission(submissions[0]);
        emit ValidatorAmountForwarded(validatorAmount);
        // 2) Handle Validator portion
        super.getValidatorAVS().handleValidatorRewards(submissions[1], validatorAmount);
    }

    function _handleUnderwriterSubmission(
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission calldata submission
    )
        private
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

        // Get all active underwriter operators registered for this AVS
        address[] memory operators =
            proposerRegistry.getActiveOperatorsForAVS(address(this));
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

        // Transfer validator portion to ValidatorAVS
        require(
            submission.token.transferFrom(
                msg.sender, address(super.getValidatorAVS()), validatorAmount
            ),
            "Validator token transfer failed"
        );
    }
}
