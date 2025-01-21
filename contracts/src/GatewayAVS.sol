// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./EigenLayerMiddleware.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title GatewayAVS
/// @notice Contract for managing gateway-specific AVS functionality and reward distribution
/// @dev Inherits from parent EigenLayerMiddleware contract
contract GatewayAVS {
    /// @notice Reference to parent EigenLayerMiddleware contract
    EigenLayerMiddleware public parentMiddleware;

    /// @notice Initializes contract with parent middleware reference
    /// @param _parentMiddleware Address of parent EigenLayerMiddleware contract
    constructor(address _parentMiddleware) {
        parentMiddleware = EigenLayerMiddleware(_parentMiddleware);
    }

    /// @notice Handles distribution of gateway rewards to operators
    /// @dev Splits rewards evenly among all registered gateway operators
    /// @param submission Base operator-directed reward submission data
    /// @param gatewayAmount Total amount allocated for gateway rewards
    /// @param originalSender Original msg.sender from parent function call
    function handleGatewayRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 gatewayAmount,
        address originalSender
    )
        external
    {
        /// Only parent middleware can call this function
        require(msg.sender == address(parentMiddleware), "GatewayAVS: Invalid caller");

        /// Approve rewards coordinator to transfer gateway rewards
        IERC20 token = submission.token;
        token.approve(address(parentMiddleware.REWARDS_COORDINATOR()), gatewayAmount);

        /// Get all active gateway operators registered for this AVS
        address[] memory operators = parentMiddleware.proposerRegistry()
            .getActiveOperatorsForAVS(address(this), AVSType.GATEWAY);
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
