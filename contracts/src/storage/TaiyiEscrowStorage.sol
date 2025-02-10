// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Storage layout for TaiyiEscrowStorage
// ╭-----------+-----------------------------+------+--------+-------+-------------------------------------------------------╮
// | Name      | Type                        | Slot | Offset | Bytes | Contract                                              |
// +=========================================================================================================================+
// | balances  | mapping(address => uint256) | 0    | 0      | 32    | src/storage/TaiyiEscrowStorage.sol:TaiyiEscrowStorage |
// |-----------+-----------------------------+------+--------+-------+-------------------------------------------------------|
// | lockBlock | mapping(address => uint256) | 1    | 0      | 32    | src/storage/TaiyiEscrowStorage.sol:TaiyiEscrowStorage |
// |-----------+-----------------------------+------+--------+-------+-------------------------------------------------------|
// | __gap     | uint256[50]                 | 2    | 0      | 1600  | src/storage/TaiyiEscrowStorage.sol:TaiyiEscrowStorage |
// ╰-----------+-----------------------------+------+--------+-------+-------------------------------------------------------╯

/// @title TaiyiEscrowStorage
/// @notice Storage contract for TaiyiEscrow containing state variables
contract TaiyiEscrowStorage {
    /// @notice Mapping of user addresses to their ETH balances
    mapping(address => uint256) internal balances;

    /// @notice Mapping of user addresses to the block number at which their funds are locked
    /// @dev Used for enforcing withdrawal lock periods
    mapping(address => uint256) internal lockBlock;

    /// @notice The period during which funds are locked after a withdrawal request
    uint256 public constant LOCK_PERIOD = 64;

    /// @notice The maximum possible value for a uint256
    uint256 public constant MAX_UINT256 = type(uint256).max;

    /// @dev Storage gap for future upgrades
    uint256[50] private __gap;
}
