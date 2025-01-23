// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EigenLayerMiddleware } from "../abstract/EigenLayerMiddleware.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";

/// @title GatewayAVS
/// @notice Manages gateway-specific AVS functionality and reward distribution.
/// @dev Inherits from the abstract EigenLayerMiddleware.
contract GatewayAVS is EigenLayerMiddleware {
    error UseRegisterOperatorToAVSWithPubKey();

    /// @notice Restricts function access to only this contract as tx.origin
    modifier onlyThisContractAsTxOrigin() {
        require(tx.origin == address(this), "Only this contract can be tx.origin");
        _;
    }

    /// @notice The portion of the reward that belongs to Gateway vs. Validator
    /// ratio expressed as a fraction of 10,000 => e.g., 2,000 means 20%.
    uint256 public GATEWAY_SHARE_BIPS; // e.g., 8000 => 80%

    /// @notice Initialize upgradeable contract.
    function initializeGatewayAVS(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator
    )
        external
        initializer
    {
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
    }

    /// @notice Special registration function for operators to register with GatewayAVS
    /// @dev This is the only way for operators to register with GatewayAVS since it requires BLS key
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
            operator, IProposerRegistry.AVSType.GATEWAY, operatorBLSPubKey
        );
    }

    /// @notice This function is required by IServiceManager but should not be used.
    /// Users must call registerOperatorToAVSWithBLS instead to provide BLS key.
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    )
        external
        override
    {
        revert UseRegisterOperatorToAVSWithPubKey();
    }

    /// @notice Processes operator rewards for both Gateway and Validator AVS components
    /// @dev Expects exactly 2 submissions in a specific order - Gateway first, then Validator
    /// @dev Each submission contains operator addresses and their corresponding reward amounts
    /// @param submissions Array containing reward submissions for Gateway and Validator
    // Todo: for operators who self delegate into GatewayAVS, we need to handle the case where for reward distribution where the fee earned won't be distributred to the validator avs
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

        // Validate Gateway submission is first
        require(
            keccak256(bytes(submissions[0].description)) == keccak256(bytes("gateway")),
            "EigenLayerMiddleware: First submission must be the Gateway portion"
        );
        // Validate Validator submission is second
        require(
            keccak256(bytes(submissions[1].description)) == keccak256(bytes("validator")),
            "EigenLayerMiddleware: Second submission must be the Validator portion"
        );

        // 1) Handle Gateway portion
        uint256 validatorAmount = _handleGatewaySubmission(submissions[0]);

        // 2) Handle Validator portion
        super.getValidatorAVS().handleValidatorRewards(submissions[1], validatorAmount);
    }

    function _handleGatewaySubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission
    )
        private
        returns (uint256 validatorAmount)
    {
        // Calculate total gateway amount
        uint256 totalAmount;
        for (uint256 i = 0; i < submission.operatorRewards.length; i++) {
            totalAmount += submission.operatorRewards[i].amount;
        }

        // Approve this contract to handle the allocated amount, then transfer it here
        submission.token.approve(address(this), totalAmount);
        require(
            submission.token.transferFrom(msg.sender, address(this), totalAmount),
            "Gateway token transfer failed"
        );

        uint256 gatewayAmount = (totalAmount * GATEWAY_SHARE_BIPS) / 10_000;
        validatorAmount = totalAmount - gatewayAmount;

        submission.token.approve(address(REWARDS_COORDINATOR), gatewayAmount);

        // Get all active gateway operators registered for this AVS
        address[] memory operators = proposerRegistry.getActiveOperatorsForAVS(
            address(this), IProposerRegistry.AVSType.GATEWAY
        );
        require(operators.length > 0, "GatewayAVS: No operators");

        // Calculate per-operator reward amount
        uint256 perOperator = gatewayAmount / operators.length;

        // Create array of operator rewards with even distribution
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            opRewards[i] = IRewardsCoordinator.OperatorReward({
                operator: operators[i],
                amount: perOperator
            });
        }

        // Todo: Sweep any leftover dust from uneven division to treasury or redistribute

        // Create final submission array with single entry
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory gatewaySubmissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);

        // Configure submission with operator rewards and metadata
        gatewaySubmissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(abi.encodePacked(submission.description, "(Gateway portion)"))
        });

        // Submit rewards distribution to coordinator
        REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(
            address(this), gatewaySubmissions
        );
    }
}
