// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

/// @title IValidatorAVS
/// @notice Interface for the ValidatorAVS contract
interface IValidatorAVS {
    /// @notice Initialize upgradeable contract
    function initializeValidatorAVS(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator
    )
        external;

    /// @notice Handles validator-based reward distribution logic
    /// @param submission The operator-directed reward submission info
    /// @param validatorAmount The total portion allocated to validators
    function handleValidatorRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 validatorAmount
    )
        external;

    /// @notice Register validators for a pod owner
    /// @param valPubKeys Array of validator BLS public keys to register
    /// @param podOwners Array of pod owner addresses
    /// @param delegatedGatewayPubKeys Array of delegated gateway public keys
    function registerValidators(
        bytes[][] calldata valPubKeys,
        address[] calldata podOwners,
        bytes[] calldata delegatedGatewayPubKeys
    )
        external;
}
