// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { GatewayAVS } from "../eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "../eigenlayer-avs/ValidatorAVS.sol";
import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { OperatorManagement } from "../libs/OperatorManagement.sol";
import { ValidatorManagement } from "../libs/ValidatorManagement.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

// Storage layout for TaiyiProposerRegistry
// ╭------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------╮
// | Name                         | Type                                                   | Slot | Offset | Bytes | Contract                                                                  |
// +===========================================================================================================================================================================================+
// | validators                   | mapping(bytes32 => struct IProposerRegistry.Validator) | 0    | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _avsToOperators              | mapping(address => struct EnumerableSet.AddressSet)    | 1    | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _avsTypes                    | mapping(address => enum IProposerRegistry.AVSType)     | 2    | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | restakingMiddlewareContracts | struct EnumerableSet.AddressSet                        | 3    | 0      | 64    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _gatewayAVS                  | contract GatewayAVS                                    | 5    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _validatorAVS                | contract ValidatorAVS                                  | 6    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _gatewayAVSAddress           | address                                                | 7    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _validatorAVSAddress         | address                                                | 8    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | validatorState               | struct ValidatorManagement.ValidatorState              | 9    | 0      | 64    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | operatorState                | struct OperatorManagement.OperatorState                | 11   | 0      | 128   | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | __gap                        | uint256[50]                                            | 15   | 0      | 1600  | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// ╰------------------------------+--------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------╯

/// @title TaiyiProposerRegistryStorage
/// @notice Storage contract for TaiyiProposerRegistry, containing all state variables
contract TaiyiProposerRegistryStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Mapping from validator pubkey hash to validator data
    mapping(bytes32 => IProposerRegistry.Validator) internal validators;

    /// @notice Mapping from AVS contract to operator addresses
    mapping(address => EnumerableSet.AddressSet) internal _avsToOperators;

    /// @notice Mapping from AVS contract to AVS type
    mapping(address => IProposerRegistry.AVSType) internal _avsTypes;

    /// @notice Set of middleware contracts authorized to call updating functions
    EnumerableSet.AddressSet internal restakingMiddlewareContracts;

    /// @notice GatewayAVS contract instance
    GatewayAVS internal _gatewayAVS;

    /// @notice ValidatorAVS contract instance
    ValidatorAVS internal _validatorAVS;

    /// @notice GatewayAVS address
    address internal _gatewayAVSAddress;

    /// @notice ValidatorAVS address
    address internal _validatorAVSAddress;

    /// @notice Cooldown period for validator opt-out in seconds
    uint256 internal constant _OPT_OUT_COOLDOWN = 7 days;

    /// @notice Validator state
    ValidatorManagement.ValidatorState internal validatorState;

    /// @notice Operator state
    OperatorManagement.OperatorState internal operatorState;

    // Storage gap for future variable additions
    uint256[50] private __gap;
}
