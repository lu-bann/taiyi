// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequestStatus } from "../types/CommonTypes.sol";

// Storage layout for TaiyiCoreStorage
// ╭----------------------+-----------------------------------------------+------+--------+-------+---------------------------------------------------╮
// | Name                 | Type                                          | Slot | Offset | Bytes | Contract                                          |
// +==================================================================================================================================================+
// | collectedTip         | uint256                                       | 0    | 0      | 32    | src/storage/TaiyiCoreStorage.sol:TaiyiCoreStorage |
// |----------------------+-----------------------------------------------+------+--------+-------+---------------------------------------------------|
// | preconferTips        | mapping(bytes32 => uint256)                   | 1    | 0      | 32    | src/storage/TaiyiCoreStorage.sol:TaiyiCoreStorage |
// |----------------------+-----------------------------------------------+------+--------+-------+---------------------------------------------------|
// | preconfRequestStatus | mapping(bytes32 => enum PreconfRequestStatus) | 2    | 0      | 32    | src/storage/TaiyiCoreStorage.sol:TaiyiCoreStorage |
// |----------------------+-----------------------------------------------+------+--------+-------+---------------------------------------------------|
// | inclusionStatusMap   | mapping(bytes32 => bool)                      | 3    | 0      | 32    | src/storage/TaiyiCoreStorage.sol:TaiyiCoreStorage |
// |----------------------+-----------------------------------------------+------+--------+-------+---------------------------------------------------|
// | __gap                | uint256[50]                                   | 4    | 0      | 1600  | src/storage/TaiyiCoreStorage.sol:TaiyiCoreStorage |
// ╰----------------------+-----------------------------------------------+------+--------+-------+---------------------------------------------------╯

/// @title TaiyiCoreStorage
/// @notice Storage contract for TaiyiCore containing state variables
contract TaiyiCoreStorage {
    /// @notice Total amount of tips collected
    uint256 internal collectedTip;

    /// @notice Mapping from preconf request hash to tip amount for each preconfer
    mapping(bytes32 => uint256) internal preconferTips;

    /// @notice Mapping from preconf request hash to its current status
    mapping(bytes32 => PreconfRequestStatus) internal preconfRequestStatus;

    /// @notice Mapping from preconf request hash to whether it has been included
    mapping(bytes32 => bool) internal inclusionStatusMap;

    /// @dev Storage gap for future upgrades
    uint256[50] private __gap;
}
