// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

/// @title IUnderwriterAVS
/// @notice Interface for the UnderwriterAVS contract
interface IUnderwriterAVS {
    /// @notice Special registration function for operators to register with UnderwriterAVS
    /// @param operator The address of the operator to register
    /// @param operatorSignature The operator's signature for AVS registration
    /// @param operatorBLSPubKey The operator's BLS public key
    function registerOperatorToAVSWithPubKey(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature,
        bytes calldata operatorBLSPubKey
    )
        external;

    /// @notice Handles distribution of underwriter rewards to operators
    /// @param submission Base operator-directed reward submission data
    /// @param underwriterAmount Total amount allocated for underwriter rewards
    function handleUnderwriterRewards(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission,
        uint256 underwriterAmount
    )
        external;

    /// @notice Initialize upgradeable contract
    function initializeUnderwriterAVS(
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
