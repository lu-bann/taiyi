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
// ╭------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------╮
// | Name                         | Type                                                                                             | Slot | Offset | Bytes | Contract                                            |
// +===============================================================================================================================================================================================================+
// | registeredOperators          | mapping(address => mapping(enum IProposerRegistry.AVSType => struct IProposerRegistry.Operator)) | 0    | 0      | 32    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | validators                   | mapping(bytes32 => struct IProposerRegistry.Validator)                                           | 1    | 0      | 32    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | operatorToValidatorPubkeys   | mapping(address => bytes[])                                                                      | 2    | 0      | 32    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | operatorBlsKeyToData         | mapping(bytes => struct IProposerRegistry.OperatorBLSData)                                       | 3    | 0      | 32    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | _avsToOperators              | mapping(address => struct EnumerableSet.AddressSet)                                              | 4    | 0      | 32    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | _avsTypes                    | mapping(address => enum IProposerRegistry.AVSType)                                               | 5    | 0      | 32    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | restakingMiddlewareContracts | struct EnumerableSet.AddressSet                                                                  | 6    | 0      | 64    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | _gatewayAVS                  | contract GatewayAVS                                                                              | 8    | 0      | 20    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | _validatorAVS                | contract ValidatorAVS                                                                            | 9    | 0      | 20    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | _gatewayAVSAddress           | address                                                                                          | 10   | 0      | 20    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | _validatorAVSAddress         | address                                                                                          | 11   | 0      | 20    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | validatorState               | struct ValidatorManagement.ValidatorState                                                        | 12   | 0      | 64    | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | operatorState                | struct OperatorManagement.OperatorState                                                          | 14   | 0      | 128   | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// |------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------|
// | __gap                        | uint256[50]                                                                                      | 18   | 0      | 1600  | src/TaiyiProposerRegistry.sol:TaiyiProposerRegistry |
// ╰------------------------------+--------------------------------------------------------------------------------------------------+------+--------+-------+-----------------------------------------------------╯

/// @title TaiyiProposerRegistryStorage
/// @notice Storage contract for TaiyiProposerRegistry, containing all state variables
contract TaiyiProposerRegistryStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Mapping from operator address to AVS type to operator data
    mapping(address => mapping(IProposerRegistry.AVSType => IProposerRegistry.Operator))
        internal registeredOperators;

    /// @notice Mapping from validator pubkey hash to validator data
    mapping(bytes32 => IProposerRegistry.Validator) internal validators;

    /// @notice Mapping from operator address to validator pubkeys
    mapping(address => bytes[]) internal operatorToValidatorPubkeys;

    /// @notice Mapping from operator BLS key to operator data
    mapping(bytes => IProposerRegistry.OperatorBLSData) internal operatorBlsKeyToData;

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
