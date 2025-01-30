// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

/// @title IGatewayAVS
/// @notice Interface for the GatewayAVS contract
interface IGatewayAVS {
    /// @notice Special registration function for operators to register with GatewayAVS
    /// @param operator The address of the operator to register
    /// @param operatorSignature The operator's signature for AVS registration
    /// @param operatorBLSPubKey The operator's BLS public key
    function registerOperatorToAVSWithPubKey(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature,
        bytes calldata operatorBLSPubKey
    )
        external;

    /// @notice Handles distribution of gateway rewards to operators
    /// @param submission Base operator-directed reward submission data
    /// @param gatewayAmount Total amount allocated for gateway rewards
    function handleGatewayRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 gatewayAmount
    )
        external;

    /// @notice Initialize upgradeable contract
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
        external;
}
