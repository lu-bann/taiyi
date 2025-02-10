// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
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
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

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
// | GATEWAY_SHARE_BIPS  | uint256                           | 9    | 0      | 32    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | gatewayAVSAddress   | address                           | 10   | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | validatorAVSAddress | address                           | 11   | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | __gap               | uint256[50]                       | 12   | 0      | 1600  | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// ╰---------------------+-----------------------------------+------+--------+-------+-------------------------------------------------------------------------╯

contract EigenLayerMiddlewareStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

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

    /// @notice Set of allowed EigenLayer strategies
    EnumerableSet.AddressSet internal strategies;

    /// @notice The address of the entity that can initiate rewards
    address internal REWARD_INITIATOR;

    /// @notice The portion of the reward that belongs to Gateway vs. Validator
    /// ratio expressed as a fraction of 10,000 => e.g., 2,000 means 20%.
    uint256 internal GATEWAY_SHARE_BIPS; // e.g., 8000 => 80%

    /// @notice The address of the gateway AVS contract
    /// @dev Used to verify operator registration in gateway AVS
    address internal gatewayAVSAddress;

    /// @notice The address of the validator AVS contract
    /// @dev Used to verify operator registration in validator AVS
    address internal validatorAVSAddress;

    uint256[50] private __gap;
}
