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

    // Validator struct containing all necessary information
    struct Validator {
        bytes pubkey;
        ValidatorStatus status;
        uint256 optOutTimestamp;
        address operator;
    }

    struct Operator {
        address operatorAddress;
        string rpc;
        address restakingMiddlewareContract;
    }

    // Events
    event ValidatorOptedIn(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorOptedOut(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorStatusChanged(bytes32 indexed pubKeyHash, ValidatorStatus status);
    event ValidatorRegistered(bytes32 indexed pubkeyHash, address indexed operator);

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    /// @param _proposerRegistry Address of the proposer registry
    /// @param _avsDirectory Address of the AVS directory
    function initialize(address _owner, address _proposerRegistry, address _avsDirectory) external;

    /// @notice Adds a new middleware contract to the registry
    /// @param middlewareContract Address of middleware contract to add
    function addRestakingMiddlewareContract(address middlewareContract) external;

    /// @notice Removes a middleware contract from the registry
    /// @param middlewareContract Address of middleware contract to remove
    function removeRestakingMiddlewareContract(address middlewareContract) external;

    /// @notice Registers a new operator
    /// @param operatorAddress The address of the operator to register
    /// @param rpcUrl The RPC URL of the operator
    /// @param middlewareContract The middleware contract address
    function registerOperator(address operatorAddress, string calldata rpcUrl, address middlewareContract) external;

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
    function registerValidator(bytes calldata pubkey, address operator) external payable;

    /// @notice Registers multiple validators in a single transaction
    /// @param pubkeys Array of BLS public keys
    /// @param operator The operator address for all validators
    function batchRegisterValidators(bytes[] calldata pubkeys, address operator) external payable;

    /// @notice Initiates the opt-out process for a validator
    /// @param pubKeyHash The hash of the validator's BLS public key
    /// @param signatureExpiry The expiry time of the signature
    /// @param signature The BLS signature proving control over the pubkey
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry, BLS12381.G2Point calldata signature) external;

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
    function getValidatorOperator(bytes calldata pubkey) external view returns (address);

    /// @notice Gets validator status by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes32 pubKeyHash) external view returns (ValidatorStatus);

    /// @notice Gets validator status by public key
    /// @param pubKey The validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes calldata pubKey) external view returns (ValidatorStatus);

    /// @notice Gets validator information by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's information
    function getValidator(bytes32 pubKeyHash) external view returns (Validator memory);

    /// @notice The cooldown period required before completing opt-out
    function OPT_OUT_COOLDOWN() external view returns (uint256);
}
