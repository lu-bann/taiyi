// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BLS12381 } from "../libs/BLS12381.sol";

interface IProposerRegistry {
    // Enum to represent the status of a proposer
    enum ValidatorStatus {
        NotRegistered,
        OptedOut,
        Active,
        OptingOut
    }

    /// @dev Different types of AVS for clearer operator organization
    enum AVSType {
        GATEWAY,
        VALIDATOR
    }

    // Validator struct containing all necessary information
    struct Validator {
        bytes pubkey;
        ValidatorStatus status;
        uint256 optOutTimestamp;
        address operator;
        bytes delegatee;
    }

    struct Operator {
        address operatorAddress;
        address restakingMiddlewareContract;
        AVSType avsType;
        bytes pubKeys;
    }

    // Events
    event ValidatorOptedIn(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorOptedOut(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorStatusChanged(bytes32 indexed pubKeyHash, ValidatorStatus status);
    event ValidatorRegistered(bytes32 indexed pubkeyHash, address indexed operator);

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    function initialize(address _owner) external;

    /// @notice Adds a new middleware contract to the registry
    /// @param middlewareContract Address of middleware contract to add
    function addRestakingMiddlewareContract(address middlewareContract) external;

    /// @notice Removes a middleware contract from the registry
    /// @param middlewareContract Address of middleware contract to remove
    function removeRestakingMiddlewareContract(address middlewareContract) external;

    /// @notice Registers a new operator
    /// @param operatorAddress The address of the operator to register
    function registerOperator(address operatorAddress) external;

    /// @notice Deregisters an existing operator
    /// @param operatorAddress The address of the operator to deregister
    function deregisterOperator(address operatorAddress) external;

    /// @notice Checks if an operator is registered in the registry
    /// @param operatorAddress The address of the operator to check
    /// @return bool True if the operator is registered, false otherwise
    function isOperatorRegistered(address operatorAddress) external view returns (bool);

    /// @notice Registers a single validator
    /// @param pubkey The BLS public key of the validator
    /// @param operator The operator address for the validator
    /// @param delegatee The address that will be delegated to for this validator
    function registerValidator(
        bytes calldata pubkey,
        address operator,
        address delegatee
    )
        external
        payable;

    /// @notice Registers multiple validators in a single transaction
    /// @param pubkeys Array of BLS public keys
    /// @param operator The operator address for all validators
    function batchRegisterValidators(
        bytes[] calldata pubkeys,
        address operator
    )
        external
        payable;

    /// @notice Initiates the opt-out process for a validator
    /// @param pubKeyHash The hash of the validator's BLS public key
    /// @param signatureExpiry The expiry time of the signature
    function initOptOut(
        bytes32 pubKeyHash,
        uint256 signatureExpiry
    )
        // BLS12381.G2Point calldata signature
        external;

    /// @notice Confirms the opt-out process after the cooldown period
    /// @param pubKeyHash The hash of the validator's BLS public key
    function confirmOptOut(bytes32 pubKeyHash) external;

    /// @notice Gets operator address for a validator
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The operator's address
    function getOperator(bytes32 pubKeyHash) external view returns (address);

    /// @notice Gets the operator address for a given validator public key
    /// @param pubkey The BLS public key of the validator
    /// @return The operator address associated with the validator
    function getValidatorOperator(bytes calldata pubkey)
        external
        view
        returns (address);

    /// @notice Gets validator status by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes32 pubKeyHash)
        external
        view
        returns (ValidatorStatus);

    /// @notice Gets validator status by public key
    /// @param pubKey The validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes calldata pubKey)
        external
        view
        returns (ValidatorStatus);

    /// @notice Gets validator information by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's information
    function getValidator(bytes32 pubKeyHash) external view returns (Validator memory);

    /// @notice Returns how many validators an operator currently controls in a given AVS.
    /// @param avs The AVS contract address (middleware)
    /// @param operator The operator address
    function getValidatorCountForOperatorInAVS(
        address avs,
        address operator
    )
        external
        view
        returns (uint256);

    /// @notice Returns a list of active operators for a given AVS.
    /// @param avs The AVS contract address (middleware)
    function getActiveOperatorsForAVS(
        address avs,
        AVSType avsType
    )
        external
        view
        returns (address[] memory);

    /// @notice Returns the total validator count for all operators in a given AVS.
    /// @param avs The AVS contract address (middleware)
    function getTotalValidatorCountForAVS(
        address avs,
        AVSType avsType
    )
        external
        view
        returns (uint256);

    /// @notice The cooldown period required before completing opt-out
    function OPT_OUT_COOLDOWN() external view returns (uint256);
}
