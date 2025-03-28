// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";

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
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";

import { IRegistry } from "@urc/IRegistry.sol";

import { EnumerableMap } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";

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
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    /// @notice Mapping of operator set IDs to strategies
    mapping(uint32 => IStrategy[]) internal operatorSetToStrategies;

    /// @notice Mapping of operator to their signed delegations
    /// @dev operator address -> registration root -> validator pubkey -> signed delegation
    mapping(
        address => mapping(bytes32 => mapping(BLS.G1Point => IRegistry.SignedDelegation))
    ) internal operatorToDelegation;

    /// @notice ProposerRegistry contract instance
    IProposerRegistry internal proposerRegistry;

    /// @notice EigenLayer AVS Directory contract
    IAVSDirectory internal AVS_DIRECTORY;

    /// @notice EigenLayer EigenPodManager contract
    IEigenPodManager internal EIGEN_POD_MANAGER;

    /// @notice EigenLayer Delegation Manager contract
    DelegationManagerStorage internal DELEGATION_MANAGER;

    /// @notice EigenLayer Strategy Manager contract
    StrategyManagerStorage internal STRATEGY_MANAGER;

    /// @notice EigenLayer Reward Coordinator contract for managing operator rewards
    IRewardsCoordinator internal REWARDS_COORDINATOR;

    /// @notice Taiyi Registry Coordinator contract for managing operator registrations
    ITaiyiRegistryCoordinator internal REGISTRY_COORDINATOR;

    /// @notice The address of the URC Registry contract
    IRegistry internal REGISTRY;

    /// @notice The address of the entity that can initiate rewards
    address internal REWARD_INITIATOR;

    /// @notice The duration of the reward period
    uint32 internal REWARD_DURATION;

    /// @notice The portion of the reward that belongs to Gateway vs. Validator
    /// ratio expressed as a fraction of 10,000 => e.g., 2,000 means 20%.
    uint256 internal UNDERWRITER_SHARE_BIPS; // e.g., 8000 => 80%

    uint256[50] private __gap;
}
