// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import { BN254 } from "../libs/BN254.sol";

import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

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

    /// @notice Defines the type of restaking service used by the protocol
    /// @dev Used to specify which restaking mechanism an operator is using
    /// @custom:enum EIGENLAYER The operator is using EigenLayer for restaking
    /// @custom:enum SYMBIOTIC The operator is using Symbiotic for restaking
    enum RestakingProtocol {
        EIGENLAYER,
        SYMBIOTIC
    }

    /// @notice Defines the type of restaking service used by the protocol
    /// @dev Used to specify which restaking mechanism an operator is using
    /// @custom:enum EIGENLAYER_VALIDATOR The operator is using EigenLayer for restaking
    /// @custom:enum EIGENLAYER_UNDERWRITER The operator is using EigenLayer for restaking
    /// @custom:enum SYMBIOTIC_VALIDATOR The operator is using Symbiotic for restaking
    /// @custom:enum SYMBIOTIC_UNDERWRITER The operator is using Symbiotic for restaking
    enum RestakingServiceTypes {
        EIGENLAYER_VALIDATOR,
        EIGENLAYER_UNDERWRITER,
        SYMBIOTIC_VALIDATOR,
        SYMBIOTIC_UNDERWRITER
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

    /// @notice Error thrown when a caller is not the restaking middleware
    error OnlyRestakingMiddleware();

    /// @notice Error thrown when a caller is not the EigenLayer middleware
    error OnlyEigenlayerMiddleware();

    /// @notice Error thrown when an operator is not registered
    error OperatorNotDeregistered();

    /// @notice Error thrown when an operator is already registered
    error OperatorAlreadyRegistered();

    /// @notice Error thrown when an operator set is not found
    error OperatorSetNotFound(uint32 operatorSetId);

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

    /// @notice Sets the EigenLayer middleware address
    /// @param _eigenlayerMiddleware The new EigenLayer middleware address
    function setEigenlayerMiddleware(address _eigenlayerMiddleware) external;

    /**
     * @notice Register an operator with the specified operator set IDs
     * @param operator The address of the operator to register
     * @param operatorSetIds The operator set IDs to register the operator with
     * @param data Additional data required for registration
     */
    function registerOperator(
        address operator,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        external;

    /**
     * @notice Register an operator with the specified service type ID
     * @param operator The address of the operator to register
     * @param serviceTypeId The service type ID that defines what kind of operator this is
     * @param data Additional data required for registration
     */
    function registerOperatorWithServiceType(
        address operator,
        uint32 serviceTypeId,
        bytes calldata data
    )
        external;

    /// @notice Deregister an operator from the specified operator set IDs
    /// @param operator The address of the operator to deregister
    /// @param operatorSetIds The operator set IDs to deregister the operator from
    function deregisterOperator(
        address operator,
        uint32[] memory operatorSetIds
    )
        external;

    /// @notice Create a new operator set with the specified strategies
    /// @param strategies Array of strategy addresses for the new operator set
    /// @return The ID of the newly created operator set
    function createOperatorSet(IStrategy[] memory strategies) external returns (uint32);

    /// @notice Get the operators in the specified operator set
    /// @param operatorSetId The ID of the operator set
    /// @return Array of operator addresses in the set
    function getOperatorSetOperators(uint32 operatorSetId)
        external
        view
        returns (address[] memory);

    /// @notice Get the operator set with the specified ID
    /// @param operatorSetId The ID of the operator set
    /// @param operator The address of the operator
    /// @return Array of operator addresses in the set
    function getOperatorFromOperatorSet(
        uint32 operatorSetId,
        address operator
    )
        external
        view
        returns (address);

    /// @notice Get the total count of operator sets
    /// @return The count of operator sets
    function getOperatorSetCount() external view returns (uint32);

    /// @notice Get the strategies in the specified operator set
    /// @param operatorSetId The ID of the operator set
    /// @return Array of strategy addresses in the set
    function getOperatorSetStrategies(uint32 operatorSetId)
        external
        view
        returns (IStrategy[] memory);

    /// @notice Add strategies to an existing operator set
    /// @param operatorSetId The ID of the operator set
    /// @param strategies Array of strategy addresses to add
    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external;

    /// @notice Remove strategies from an existing operator set
    /// @param operatorSetId The ID of the operator set
    /// @param strategies Array of strategy addresses to remove
    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external;

    /// @notice Get all operator sets that an operator has allocated magnitude to
    /// @param operator The operator whose allocated sets to fetch
    /// @return Array of operator sets that the operator has allocated magnitude to
    function getOperatorAllocatedOperatorSets(address operator)
        external
        view
        returns (OperatorSet[] memory);

    /// @notice Get all strategies that an operator has allocated magnitude to in a specific operator set
    /// @param operator The operator whose allocated strategies to fetch
    /// @param operatorSetId The ID of the operator set to query
    /// @return Array of strategies that the operator has allocated magnitude to in the operator set
    function getOperatorAllocatedStrategies(
        address operator,
        uint32 operatorSetId
    )
        external
        view
        returns (IStrategy[] memory);

    /// @notice Get an operator's allocation info for a specific strategy in an operator set
    /// @param operator The operator whose allocation to fetch
    /// @param operatorSetId The ID of the operator set to query
    /// @param strategy The strategy to query
    /// @return The operator's allocation info for the strategy in the operator set
    function getOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 operatorSetId,
        IStrategy strategy
    )
        external
        view
        returns (IAllocationManagerTypes.Allocation memory);

    /// @notice Get all operator sets and allocations for a specific strategy that an operator has allocated magnitude to
    /// @param operator The operator whose allocations to fetch
    /// @param strategy The strategy to query
    /// @return Array of operator sets and corresponding allocations for the strategy
    function getOperatorStrategyAllocations(
        address operator,
        IStrategy strategy
    )
        external
        view
        returns (OperatorSet[] memory, IAllocationManagerTypes.Allocation[] memory);

    /// @notice Get the information for a specific operator
    /// @param operator The address of the operator
    /// @return The operator's information
    function getOperator(address operator) external view returns (OperatorInfo memory);

    /// @notice Get the operator ID for a specific operator
    /// @param operator The address of the operator
    /// @return The operator's unique identifier
    function getOperatorId(address operator) external view returns (bytes32);

    /// @notice Get the operator address for a specific operator ID
    /// @param operatorId The operator's unique identifier
    /// @return The operator's address
    function getOperatorFromId(bytes32 operatorId) external view returns (address);

    /// @notice Get the registration status for a specific operator
    /// @param operator The address of the operator
    /// @return The operator's registration status
    function getOperatorStatus(address operator) external view returns (OperatorStatus);

    /// @notice Returns the message hash that an operator must sign to register their BLS public key
    /// @param operator The address of the operator
    /// @return The hash to sign as a BN254.G1Point
    function pubkeyRegistrationMessageHash(address operator)
        external
        view
        returns (BN254.G1Point memory);

    /// @notice Calculates the message hash that an operator must sign to register their BLS public key
    /// @param operator The address of the operator
    /// @return The calculated hash
    function calculatePubkeyRegistrationMessageHash(address operator)
        external
        view
        returns (bytes32);
}
