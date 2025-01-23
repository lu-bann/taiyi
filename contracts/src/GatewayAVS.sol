// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./EigenLayerMiddleware.sol";

import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
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
        onlyNonRegisteredOperator
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

    /// @notice Creates operator-directed rewards to split between operators and their delegated stakers
    /// @param operatorDirectedRewardsSubmissions The rewards submissions to process
    function _createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions
    )
        internal
        override
        onlyRewardsInitiator
    {
        // We expect exactly 2 submissions: the first for Gateway, the second for Validator
        require(
            submissions.length == 2,
            "EigenLayerMiddleware: Must pass exactly 2 submissions"
        );

        // Verify that the first submission is for the Gateway portion by checking its description
        require(
            keccak256(bytes(submissions[0].description)) == keccak256(bytes("gateway")),
            "EigenLayerMiddleware: First submission must be the Gateway portion"
        );
        // Verify that the second submission is for the Validator portion by checking its description
        require(
            keccak256(bytes(submissions[1].description)) == keccak256(bytes("validator")),
            "EigenLayerMiddleware: Second submission must be the Validator portion"
        );

        // Handle Gateway submission
        _handleAVSSubmission(
            submissions[0],
            address(gatewayAVS),
            gatewayAVS.handleGatewayRewards,
            "Gateway"
        );

        // Handle Validator submission
        _handleAVSSubmission(
            submissions[1],
            address(validatorAVS),
            validatorAVS.handleValidatorRewards,
            "Validator"
        );
    }

    function _handleAVSSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission memory submission,
        address avsAddress,
        function(
            IRewardsCoordinator.OperatorDirectedRewardsSubmission memory,
            uint256
        ) external handleRewards,
        string memory avsType
    )
        private
    {
        // Calculate total reward amount
        uint256 totalAmount;
        for (uint256 i = 0; i < submission.operatorRewards.length; i++) {
            totalAmount += submission.operatorRewards[i].amount;
        }

        // First approve AVS to handle the allocated amount
        submission.token.approve(avsAddress, totalAmount);

        // Then transfer tokens from caller to this contract
        require(
            submission.token.transferFrom(msg.sender, address(this), totalAmount),
            string(abi.encodePacked(avsType, " token transfer failed"))
        );

        // Invoke AVS logic
        handleRewards(submission, totalAmount, msg.sender);
    }

    /// @notice Handles distribution of gateway rewards to operators
    /// @dev Splits rewards evenly among all registered gateway operators
    /// @param submission Base operator-directed reward submission data
    /// @param gatewayAmount Total amount allocated for gateway rewards
    function handleGatewayRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 gatewayAmount
    )
        internal
    {
        /// Only parent middleware can call this function
        require(msg.sender == address(parentMiddleware), "GatewayAVS: Invalid caller");

        /// Approve rewards coordinator to transfer gateway rewards
        IERC20 token = submission.token;
        token.approve(address(parentMiddleware.REWARDS_COORDINATOR()), gatewayAmount);

        /// Get all active gateway operators registered for this AVS
        address[] memory operators = parentMiddleware.proposerRegistry()
            .getActiveOperatorsForAVS(address(this), IProposerRegistry.AVSType.GATEWAY);
        require(operators.length > 0, "GatewayAVS: No operators");

        /// Calculate per-operator reward amount
        uint256 perOperator = gatewayAmount / operators.length;

        /// Create array of operator rewards with even distribution
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            opRewards[i] = IRewardsCoordinator.OperatorReward({
                operator: operators[i],
                amount: perOperator
            });
        }

        // TODO: Sweep any leftover dust from uneven division to treasury or redistribute

        /// Create final submission array with single entry
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory gatewaySubmissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);

        /// Configure submission with operator rewards and metadata
        gatewaySubmissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(
                abi.encodePacked(submission.description, " (Gateway portion)")
            )
        });

        /// Submit rewards distribution to coordinator
        parentMiddleware.REWARDS_COORDINATOR().createOperatorDirectedAVSRewardsSubmission(
            address(this), gatewaySubmissions
        );
    }
}
