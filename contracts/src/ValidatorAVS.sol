// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./EigenLayerMiddleware.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title ValidatorAVS
/// @notice A standalone AVS for validator distribution. Receives a
///         validator-portion from the parent EigenLayerMiddleware
///         and splits it by operator validator counts.
contract ValidatorAVS {
    EigenLayerMiddleware public parentMiddleware;

    constructor(address _parentMiddleware) {
        parentMiddleware = EigenLayerMiddleware(_parentMiddleware);
    }

    /// @notice Handles validator-based reward distribution logic.
    /// @dev Distributes reward among operators proportional to
    ///      their validator count in this AVS.
    /// @param submission The operator-directed reward submission info.
    /// @param validatorAmount The total portion allocated to validators.
    /// @param originalSender The parent function's msg.sender.
    function handleValidatorRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 validatorAmount,
        address originalSender
    )
        external
    {
        require(msg.sender == address(parentMiddleware), "ValidatorAVS: Invalid caller");

        // Approve RewardsCoordinator to pull the validator portion
        IERC20 token = submission.token;
        token.approve(address(parentMiddleware.REWARDS_COORDINATOR()), validatorAmount);

        // Get validator operators and total count for this AVS
        address[] memory operators =
            parentMiddleware.proposerRegistry().getActiveOperatorsForAVS(address(this));
        uint256 totalValidatorCount = parentMiddleware.proposerRegistry()
            .getTotalValidatorCountForAVS(address(this));

        // Build array of OperatorRewards proportionally
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            new IRewardsCoordinator.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            uint256 opValidatorCount = parentMiddleware.proposerRegistry()
                .getValidatorCountForOperatorInAVS(address(this), operators[i]);

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

        parentMiddleware.REWARDS_COORDINATOR().createOperatorDirectedAVSRewardsSubmission(
            address(this), validatorSubmissions
        );
    }
}
