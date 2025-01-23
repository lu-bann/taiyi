// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./EigenLayerMiddleware.sol";

import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";

/// @title ValidatorAVS
/// @notice A standalone AVS for validator distribution. Receives a
///         validator-portion from the parent EigenLayerMiddleware
///         and splits it by operator validator counts.
contract ValidatorAVS {
    /// @notice The address of the gateway AVS contract
    /// @dev Used to verify operator registration in gateway AVS
    address public gatewayAVSAddress;

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
    modifier onlyPodOwnerOrOperator() {
        if (
            msg.sender != podOwner
                && msg.sender != DELEGATION_MANAGER.delegatedTo(podOwner)
        ) {
            revert SenderNotPodOwnerOrOperator();
        }
    }

    /// @notice Modifier that restricts function access to only the gateway AVS contract
    /// @dev Reverts if msg.sender is not the gateway AVS contract address
    modifier onlyGatewayAVS() {
        require(
            msg.sender == gatewayAVSAddress, "ValidatorAVS: caller is not gateway AVS"
        );
        _;
    }

    /// @notice Initialize upgradeable contract.
    function initializeValidatorAVS(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator,
        address _gatewayAVSAddress
    )
        external
        initializer
    {
        // Reuse base class initializer
        super.initialize(
            _owner,
            _proposerRegistry,
            _avsDirectory,
            _delegationManager,
            _strategyManager,
            _eigenPodManager,
            _rewardCoordinator,
            _rewardInitiator
        );
        gatewayAVSAddress = _gatewayAVSAddress;
    }

    // ========= OVERRIDE FUNCTIONS =========

    /// @notice Override of createOperatorDirectedAVSRewardsSubmission that redirects to GatewayAVS
    /// @dev This function always reverts and directs users to use GatewayAVS for reward distribution
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
    )
        public
        override
    {
        revert UseGatewayAVSForRewards(gatewayAVSAddress);
    }

    /// @dev Internal function that registers an operator.
    function _registerOperatorToAvs(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    )
        internal
        override
        onlyEigenCoreOperator
        onlyNonRegisteredOperator
    {
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
        proposerRegistry.registerOperator(
            operator, IProposerRegistry.AVSType.VALIDATOR, bytes("")
        );
    }

    /// @notice Internal function to register multiple validators for a pod owner
    /// @dev Enforces several conditions before registering validators:
    ///      1. Gateway public key must be non-empty (meaning an actual delegate is chosen).
    ///      2. The operator delegated by the EigenPod owner must already be registered:
    ///         - in the Gateway AVS Directory (primary restaking AVS).
    ///         - in the TaiyiProposerRegistry with the correct AVSType.
    ///      3. The pod owner must have an active EigenPod (already created).
    ///      4. Each validator BLS public key must already be active within EigenLayer.
    ///
    ///      This function also covers the "self-delegation" scenario, where the pod owner
    ///      acts as its own GatewayAVS operator.
    ///
    ///      For each validator registered, the contract emits a ValidatorOperatorRegistered event.
    ///      Off-chain, a service in "commit boost" listens to this event, and uses the information
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
    /// @param delegatedGatewayPubKey The delegated gateway public key (cannot be empty)
    function _registerValidators(
        bytes[] calldata valPubKeys,
        address podOwner,
        bytes calldata delegatedGatewayPubKey
    )
        internal
        override
        onlyPodOwnerOrOperator
    {
        require(
            delegatedGatewayPubKey.length > 0,
            "ValidatorAVS: Must choose a valid Gateway delegate"
        );

        // Get the operator delegated to by the pod owner. EigenPod owner could be self-delegated
        address operator = DELEGATION_MANAGER.delegatedTo(podOwner);

        // Check if operator is registered in proposer registry
        if (!proposerRegistry.isOperatorRegisteredInGatewayAVS(operator)) {
            revert OperatorIsNotYetRegisteredInTaiyiProposerRegistry();
        }

        // Check if operator is registered with the gateway AVS
        if (
            AVS_DIRECTORY.avsOperatorStatus(gatewayAVSAddress, operator)
                != IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
        ) {
            revert OperatorIsNotYetRegisteredInTaiyiGatewayAVS();
        }

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

            // Register validator in proposer registry with delegatedGatewayPubKey as delegatee
            proposerRegistry.registerValidator(
                valPubKeys[i], operator, delegatedGatewayPubKey
            );

            // Emit event to track validator registration
            emit ValidatorOperatorRegistered(
                operator, address(this), delegatedGatewayPubKey, valPubKeys[i]
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
        // Approve RewardsCoordinator to pull the validator portion
        IERC20 token = submission.token;
        token.approve(address(REWARDS_COORDINATOR()), validatorAmount);

        // Get validator operators and total count for this AVS
        address[] memory operators = proposerRegistry.getActiveOperatorsForAVS(
            address(this), IProposerRegistry.AVSType.VALIDATOR
        );
        uint256 totalValidatorCount = proposerRegistry.getTotalValidatorCountForAVS(
            address(this), IProposerRegistry.AVSType.VALIDATOR
        );

        // Build array of OperatorRewards proportionally
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            uint256 opValidatorCount = proposerRegistry.getValidatorCountForOperatorInAVS(
                address(this), operators[i]
            );

            // Share of the total validatorAmount = amount * (opCount/totalCount)
            uint256 share = (totalValidatorCount == 0)
                ? 0
                : validatorAmount * (opValidatorCount / totalValidatorCount);

            opRewards[i] = IRewardsCoordinator.OperatorReward({
                operator: operators[i],
                amount: share
            });
        }

        // Combine into a single submission
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory
            validatorSubmissions =
                new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);

        validatorSubmissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(
                abi.encodePacked(submission.description, " (Validator portion)")
            )
        });

        REWARDS_COORDINATOR().createOperatorDirectedAVSRewardsSubmission(
            address(this), validatorSubmissions
        );
    }
}
