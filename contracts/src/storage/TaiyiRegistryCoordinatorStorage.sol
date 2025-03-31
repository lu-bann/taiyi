// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import {
    IAllocationManager,
    IAllocationManagerTypes,
    OperatorSet
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

abstract contract TaiyiRegistryCoordinatorStorage is ITaiyiRegistryCoordinator {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice The EIP-712 typehash used for registering BLS public keys
    bytes32 public constant PUBKEY_REGISTRATION_TYPEHASH =
        keccak256("BN254PubkeyRegistration(address operator)");

    /// @notice Index for flag that pauses operator registration
    uint8 internal constant PAUSED_REGISTER_OPERATOR = 0;

    /// @notice Index for flag that pauses operator deregistration
    uint8 internal constant PAUSED_DEREGISTER_OPERATOR = 1;

    /// @notice the Socket Registry contract that will keep track of operators' sockets (arbitrary strings)
    ISocketRegistry public socketRegistry;

    /// @notice the Pubkey Registry contract that will keep track of operators' public keys
    IPubkeyRegistry public pubkeyRegistry;

    /// EigenLayer contracts
    /// @notice the AllocationManager that tracks OperatorSets and Slashing in EigenLayer
    IAllocationManager public allocationManager;

    /// @notice the current number of operator sets supported by the registry coordinator
    uint32 public operatorSetCounter;

    /// @notice maps operator set id => operator addresses
    mapping(uint32 => EnumerableSet.AddressSet) internal _operatorSets;

    /// @notice maps operator address => operator id and status
    mapping(address => OperatorInfo) internal _operatorInfo;

    /// @notice The avs address for this AVS (used for UAM integration in EigenLayer)
    address public eigenlayerMiddleware;

    /// @notice The restaking middleware addresses
    EnumerableSet.AddressSet internal restakingMiddleware;

    /// @notice The restaking protocol for each restaking middleware
    mapping(address => RestakingProtocol) internal restakingProtocol;

    constructor(IAllocationManager _allocationManager) {
        allocationManager = _allocationManager;
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[50] private __GAP;
}
