// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { GatewayAVS } from "../eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "../eigenlayer-avs/ValidatorAVS.sol";
import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { EigenLayerOperatorManagement } from "../libs/EigenLayerOperatorManagement.sol";
import { SymbioticOperatorManagement } from "../libs/SymbioticOperatorManagement.sol";
import { ValidatorManagement } from "../libs/ValidatorManagement.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
// ╭-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------╮
// | Name                        | Type                                                            | Slot | Offset | Bytes | Contract                                                                  |
// +===================================================================================================================================================================================================+
// | validators                  | mapping(bytes32 => struct IProposerRegistry.Validator)          | 0    | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _avsTypes                   | mapping(address => enum IProposerRegistry.RestakingServiceType) | 1    | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _gatewayAVS                 | contract GatewayAVS                                             | 2    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _validatorAVS               | contract ValidatorAVS                                           | 3    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _gatewayAVSAddress          | address                                                         | 4    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _validatorAVSAddress        | address                                                         | 5    | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | validatorState              | struct ValidatorManagement.ValidatorState                       | 6    | 0      | 64    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | eigenLayerOperatorState     | struct EigenLayerOperatorManagement.EigenLayerOperatorState     | 8    | 0      | 96    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | symbioticOperatorState      | struct SymbioticOperatorManagement.SymbioticOperatorState       | 11   | 0      | 96    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _symbioticMiddlewareAddress | address                                                         | 14   | 0      | 20    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _gatewaySubnetwork          | bytes32                                                         | 15   | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | _validatorSubnetwork        | bytes32                                                         | 16   | 0      | 32    | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// |-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------|
// | __gap                       | uint256[50]                                                     | 17   | 0      | 1600  | src/storage/TaiyiProposerRegistryStorage.sol:TaiyiProposerRegistryStorage |
// ╰-----------------------------+-----------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------╯

/// @title TaiyiProposerRegistryStorage
/// @notice Storage contract for TaiyiProposerRegistry, containing all state variables
contract TaiyiProposerRegistryStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Mapping from validator pubkey hash to validator data
    mapping(bytes32 => IProposerRegistry.Validator) internal validators;

    /// @notice Mapping from AVS contract to AVS type
    mapping(address => IProposerRegistry.RestakingServiceType) internal _avsTypes;

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

    /// @notice EigenLayer operator state
    EigenLayerOperatorManagement.EigenLayerOperatorState internal eigenLayerOperatorState;

    /// @notice Symbiotic operator state
    SymbioticOperatorManagement.SymbioticOperatorState internal symbioticOperatorState;

    /// @notice Address of the symbiotic middleware contract
    address internal _symbioticMiddlewareAddress;

    /// @notice Symbiotic network subnetwork for the gateway
    bytes32 internal _gatewaySubnetwork;

    /// @notice Symbiotic network subnetwork for the validator
    bytes32 internal _validatorSubnetwork;

    // Storage gap for future variable additions
    uint256[50] private __gap;
}
