// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";

import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import {
    IAllocationManager,
    IAllocationManagerTypes,
    OperatorSet
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

abstract contract TaiyiRegistryCoordinatorStorage is ITaiyiRegistryCoordinator {
    /**
     *
     *                            CONSTANTS AND IMMUTABLES
     *
     */

    /// @notice The EIP-712 typehash used for registering BLS public keys
    bytes32 public constant PUBKEY_REGISTRATION_TYPEHASH =
        keccak256("BN254PubkeyRegistration(address operator)");
    /// @notice The basis point denominator
    uint16 internal constant BIPS_DENOMINATOR = 10_000;
    /// @notice Index for flag that pauses operator registration
    uint8 internal constant PAUSED_REGISTER_OPERATOR = 0;
    /// @notice Index for flag that pauses operator deregistration
    uint8 internal constant PAUSED_DEREGISTER_OPERATOR = 1;
    /// @notice Index for flag pausing operator stake updates
    uint8 internal constant PAUSED_UPDATE_OPERATOR = 2;

    /// @notice the Socket Registry contract that will keep track of operators' sockets (arbitrary strings)
    ISocketRegistry public immutable socketRegistry;
    /// @notice the Pubkey Registry contract that will keep track of operators' public keys
    IPubkeyRegistry public immutable pubkeyRegistry;

    /// EigenLayer contracts
    /// @notice the AllocationManager that tracks OperatorSets and Slashing in EigenLayer
    IAllocationManager public immutable allocationManager;

    /// @notice the current number of operator sets supported by the registry coordinator
    uint32 public operatorSetCount;

    /// @notice maps operator address => operator id and status
    mapping(address => OperatorInfo) internal _operatorInfo;

    /// @notice the dynamic-length array of the registries this coordinator is coordinating
    /// @dev DEPRECATED: This slot is no longer used but kept for storage layout compatibility
    address[] private registries;

    /// @notice the address of the entity allowed to eject operators from the AVS
    address public ejector;

    /// @notice the last timestamp an operator was ejected
    mapping(address => uint256) public lastEjectionTimestamp;

    /// @notice the delay in seconds before an operator can reregister after being ejected
    uint256 public ejectionCooldown;

    /// @notice The avs address for this AVS (used for UAM integration in EigenLayer)
    /// @dev NOTE: Updating this value will break existing OperatorSets and UAM integration.
    /// This value should only be set once.
    address public avs;

    /// @notice The restaking middleware address
    address public restakingMiddleware;

    /// @notice The current quorum count
    uint256 public quorumCount;

    constructor(
        IPubkeyRegistry _pubkeyRegistry,
        ISocketRegistry _socketRegistry,
        IAllocationManager _allocationManager
    ) {
        pubkeyRegistry = _pubkeyRegistry;
        socketRegistry = _socketRegistry;
        allocationManager = _allocationManager;
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[48] private __GAP; // reduced from 50 to 48 to account for new state variables
}
