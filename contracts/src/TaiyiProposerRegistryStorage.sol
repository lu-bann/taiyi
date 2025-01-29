// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { GatewayAVS } from "./eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "./eigenlayer-avs/ValidatorAVS.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

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
}
