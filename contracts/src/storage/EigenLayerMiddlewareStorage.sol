// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { DelegationStore } from "../eigenlayer-avs/EigenLayerMiddleware.sol";
import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { DelegationManagerStorage } from
    "@eigenlayer-contracts/src/contracts/core/DelegationManagerStorage.sol";
import { StrategyManagerStorage } from
    "@eigenlayer-contracts/src/contracts/core/StrategyManagerStorage.sol";
import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IEigenPodManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPodManager.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRegistry } from "@urc/IRegistry.sol";

// Storage layout for EigenLayerMiddleware
// ╭---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------╮
// | Name                | Type                              | Slot | Offset | Bytes | Contract                                                                |
// +===========================================================================================================================================================+
// | proposerRegistry    | contract IProposerRegistry        | 0    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | AVS_DIRECTORY       | contract IAVSDirectory            | 1    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | EIGEN_POD_MANAGER   | contract IEigenPodManager         | 2    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | DELEGATION_MANAGER  | contract DelegationManagerStorage | 3    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | STRATEGY_MANAGER    | contract StrategyManagerStorage   | 4    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REWARDS_COORDINATOR | contract IRewardsCoordinator      | 5    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | strategies          | struct EnumerableSet.AddressSet   | 6    | 0      | 64    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REWARD_INITIATOR    | address                           | 8    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | UNDERWRITER_SHARE_BIPS  | uint256                           | 9    | 0      | 32    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | gatewayAVSAddress   | address                           | 10   | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | validatorAVSAddress | address                           | 11   | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | __gap               | uint256[50]                       | 12   | 0      | 1600  | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// ╰---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------╯

abstract contract EigenLayerMiddlewareStorage {
    // ========= CONSTANTS =========

    /// @notice Proposed reward duration is 1 day (in seconds)
    uint256 public constant REWARD_DURATION = 1 days;

    // ========= STATE VARIABLES =========

    struct DelegationInfo {
        bytes32 registrationRoot;
        IRegistry.SignedDelegation delegation;
    }

    /// @notice EigenLayer's AVS Directory contract
    IAVSDirectory public immutable AVS_DIRECTORY;

    /// @notice EigenLayer's Delegation Manager contract
    DelegationManagerStorage public immutable DELEGATION_MANAGER;

    /// @notice EigenLayer's Strategy Manager contract
    StrategyManagerStorage public immutable STRATEGY_MANAGER;

    /// @notice EigenLayer's EigenPod Manager contract
    IEigenPodManager public immutable EIGEN_POD_MANAGER;

    /// @notice EigenLayer's Reward Coordinator contract
    IRewardsCoordinator public immutable REWARDS_COORDINATOR;

    /// @notice Underwriter share in basis points
    uint256 public UNDERWRITER_SHARE_BIPS;

    /// @notice Registry contract
    IRegistry public immutable REGISTRY;

    /// @notice Reward Initiator address
    address public immutable REWARD_INITIATOR;

    /// @notice Registry Coordinator contract
    ITaiyiRegistryCoordinator public immutable REGISTRY_COORDINATOR;

    /// @notice Proposer Registry contract
    IProposerRegistry public immutable proposerRegistry;

    /// @notice Optimized storage for operator delegations
    /// @dev operator address -> registration root -> delegation store mapping
    mapping(address => mapping(bytes32 => DelegationStore)) internal operatorDelegations;

    /// @notice Optimized storage for operator registration roots
    /// @dev operator address -> registration root mapping
    mapping(address => EnumerableSet.Bytes32Set) internal operatorRegistrationRoots;

    uint256[50] private __gap;
}
