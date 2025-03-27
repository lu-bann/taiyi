// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { BN254 } from "../libs/BN254.sol";

/// @title Storage contract for the PubkeyRegistry
/// @notice Defines and manages the storage layout for the PubkeyRegistry contract
abstract contract PubkeyRegistryStorage {
    /// @dev Returns the hash of the zero pubkey aka BN254.G1Point(0,0)
    bytes32 internal constant ZERO_PK_HASH =
        hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";

    /// @notice The registry coordinator contract
    ITaiyiRegistryCoordinator internal immutable registryCoordinator;

    /// @notice Mapping from operator address to their G1 public key
    mapping(address => BN254.G1Point) internal operatorToPubkey;

    /// @notice Mapping from operator address to their G2 public key
    mapping(address => BN254.G2Point) internal operatorToPubkeyG2;

    /// @notice Mapping from operator address to their public key hash
    mapping(address => bytes32) internal operatorToPubkeyHash;

    /// @notice Mapping from public key hash to operator address
    mapping(bytes32 => address) internal pubkeyHashToOperator;

    /// @notice Constructor to set the registry coordinator
    /// @param _registryCoordinator Address of the registry coordinator contract
    constructor(ITaiyiRegistryCoordinator _registryCoordinator) {
        registryCoordinator = _registryCoordinator;
    }
}
