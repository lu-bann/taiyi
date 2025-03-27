// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/// @title ITaiyiRegistryCoordinator
/// @notice Interface for the TaiyiRegistryCoordinator contract
interface ITaiyiRegistryCoordinator {
    /// @notice Represents the registration state of an operator.
    /// @dev Used to track an operator's lifecycle in the system.
    /// @custom:enum NEVER_REGISTERED The operator has never registered with the system.
    /// @custom:enum REGISTERED The operator is currently registered and active.
    /// @custom:enum DEREGISTERED The operator was previously registered but has since deregistered.
    enum OperatorStatus {
        NEVER_REGISTERED,
        REGISTERED,
        DEREGISTERED
    }

    /// @notice Core data structure for tracking operator information.
    /// @dev Links an operator's unique identifier with their current registration status.
    /// @param operatorId Unique identifier for the operator, typically derived from their BLS public key.
    /// @param status Current registration state of the operator in the system.
    struct OperatorInfo {
        bytes32 operatorId;
        OperatorStatus status;
    }

    /// @notice Error thrown when an operator is not registered
    error NotRegistered();

    /// @notice Error thrown when an operator is not registered during ejection
    error OperatorNotRegistered();

    /// @notice Error thrown when an invalid operator set ID is provided
    error InvalidOperatorSetId();

    /// @notice Error thrown when a caller is not the ejector
    error OnlyEjector();

    /// @notice Error thrown when a caller is not the allocation manager
    error OnlyAllocationManager();

    /// @notice Emitted when an operator's socket is updated
    /// @param operatorId The operator's unique identifier
    /// @param socket The new socket value
    event OperatorSocketUpdate(bytes32 indexed operatorId, string socket);

    /// @notice Emitted when the ejector address is updated
    /// @param previousEjector The previous ejector address
    /// @param newEjector The new ejector address
    event EjectorUpdated(address indexed previousEjector, address indexed newEjector);

    /// @notice Emitted when the restaking middleware address is updated
    /// @param previousMiddleware The previous middleware address
    /// @param newMiddleware The new middleware address
    event RestakingMiddlewareUpdated(
        address indexed previousMiddleware, address indexed newMiddleware
    );

    /// @notice Updates the socket address for the calling operator
    /// @param socket The new socket address to set
    function updateSocket(string memory socket) external;

    /// @notice Sets the restaking middleware address
    /// @param _restakingMiddleware The new restaking middleware address
    function setRestakingMiddleware(address _restakingMiddleware) external;
}
