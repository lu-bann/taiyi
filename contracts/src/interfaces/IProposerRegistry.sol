// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IGatewayAVS } from "./IGatewayAVS.sol";
import { IValidatorAVS } from "./IValidatorAVS.sol";

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
        bytes blsKey;
    }

    // Events
    event ValidatorOptedIn(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorOptedOut(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorStatusChanged(bytes32 indexed pubKeyHash, ValidatorStatus status);
    event ValidatorRegistered(bytes32 indexed pubkeyHash, address indexed operator);

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    function initialize(
        address _owner,
        address _aveDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator,
        uint256 _gatewayShareBips
    )
        external;

    /// @notice Adds a new middleware contract to the registry
    /// @param middlewareContract Address of middleware contract to add
    function addRestakingMiddlewareContract(address middlewareContract) external;

    /// @notice Removes a middleware contract from the registry
    /// @param middlewareContract Address of middleware contract to remove
    function removeRestakingMiddlewareContract(address middlewareContract) external;

    /// @notice Registers a new operator
    /// @param operatorAddress The address of the operator to register
    /// @param avsType The type of AVS (GATEWAY or VALIDATOR)
    /// @param blsKey The BLS public key for the operator (only for GATEWAY type)
    function registerOperator(
        address operatorAddress,
        AVSType avsType,
        bytes calldata blsKey
    )
        external;

    /// @notice Deregisters an existing operator
    /// @param operatorAddress The address of the operator to deregister
    function deregisterOperator(address operatorAddress) external;

    /// @notice Registers a single validator
    /// @param pubkey The BLS public key of the validator
    /// @param operator The operator address for the validator
    /// @param delegatee The delegatee public key for this validator
    function registerValidator(
        bytes calldata pubkey,
        address operator,
        bytes calldata delegatee
    )
        external
        payable;

    /// @notice Registers multiple validators in a single transaction
    /// @param pubkeys Array of BLS public keys
    /// @param operator The operator address for all validators
    function batchRegisterValidators(
        bytes[] calldata pubkeys,
        address operator,
        bytes[] calldata delegatee
    )
        external
        payable;

    /// @notice Initiates the opt-out process for a validator
    /// @param pubKeyHash The hash of the validator's BLS public key
    /// @param signatureExpiry The expiry time of the signature
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry) external;

    /// @notice Confirms validator opt-out after cooldown period
    /// @param pubKeyHash The hash of the validator's BLS public key
    function confirmOptOut(bytes32 pubKeyHash) external;

    /// @notice Gets the GatewayAVS address
    /// @return The address of the GatewayAVS contract
    function gatewayAVSAddress() external view returns (address);

    /// @notice Checks if an operator is active in a specific AVS
    /// @param avs The address of the AVS to check
    /// @param operator The address of the operator to check
    /// @return bool True if the operator is active in the AVS
    function isOperatorActiveInAVS(
        address avs,
        address operator
    )
        external
        view
        returns (bool);

    /// @notice Gets the ValidatorAVS address
    /// @return The address of the ValidatorAVS contract
    function validatorAVSAddress() external view returns (address);

    /// @notice Gets the GatewayAVS contract instance
    /// @return The GatewayAVS contract instance
    function gatewayAVS() external view returns (IGatewayAVS);

    /// @notice Gets the ValidatorAVS contract instance
    /// @return The ValidatorAVS contract instance
    function validatorAVS() external view returns (IValidatorAVS);

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

    /// @notice Gets the number of validators registered to an operator for a specific AVS
    /// @param avs The address of the AVS contract
    /// @param operator The address of the operator
    /// @return The number of validators registered to the operator for the AVS
    function getValidatorCountForOperatorInAVS(
        address avs,
        address operator
    )
        external
        view
        returns (uint256);

    function getRegisteredOperator(address operatorAddr)
        external
        view
        returns (Operator memory, Operator memory);

    /// @notice Returns active operators for a specific AVS type
    /// @param avs The address of the AVS
    /// @param avsType The AVSType (GATEWAY or VALIDATOR)
    /// @return Array of operator addresses
    function getActiveOperatorsForAVS(
        address avs,
        AVSType avsType
    )
        external
        view
        returns (address[] memory);

    /// @notice Returns the total validator count for a specific AVS type
    /// @param avs The address of the AVS
    /// @param avsType The AVSType (GATEWAY or VALIDATOR)
    /// @return The total count of validators
    function getTotalValidatorCountForAVS(
        address avs,
        AVSType avsType
    )
        external
        view
        returns (uint256);

    /// @notice Returns the AVS type for a given AVS address
    /// @param avs The address of the AVS
    /// @return The AVS type
    function getAVSType(address avs) external view returns (AVSType);

    /// @notice Checks if an operator is registered in the AVS
    /// @param operatorAddress The address of the operator to check
    /// @param avsType The type of AVS
    /// @return True if registered in the AVS
    function isOperatorRegisteredInAVS(
        address operatorAddress,
        AVSType avsType
    )
        external
        view
        returns (bool);

    /// @notice Sets the AVS type for a given AVS address
    /// @param avs The address of the AVS
    /// @param avsType The type to set
    function setAVSType(address avs, AVSType avsType) external;

    /// @notice The cooldown period required before completing opt-out
    function OPT_OUT_COOLDOWN() external view returns (uint256);
}
