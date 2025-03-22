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

    /// @dev Different types of restaking services and their roles
    enum RestakingServiceType {
        // EigenLayer services
        EIGENLAYER_GATEWAY, // Gateway operator in EigenLayer
        EIGENLAYER_VALIDATOR // Validator operator in EigenLayer

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
        RestakingServiceType serviceType;
        bytes blsKey;
    }

    /// @notice Struct to store operator BLS key data
    struct OperatorBLSData {
        address operator;
        RestakingServiceType serviceType;
    }

    // Events
    event ValidatorOptedIn(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorOptedOut(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorStatusChanged(bytes32 indexed pubKeyHash, ValidatorStatus status);
    event ValidatorRegistered(bytes32 indexed pubkeyHash, address indexed operator);
    event OperatorRegistered(
        address indexed operator,
        address indexed avsContract,
        RestakingServiceType serviceType
    );
    event OperatorDeregistered(address indexed operator, address indexed avsContract);
    event OperatorBLSKeyUpdated(address indexed operator, bytes oldKey, bytes newKey);
    event RestakingServiceTypeSet(
        address indexed restakingServiceAddress, RestakingServiceType serviceType
    );
    event ValidatorsOptedOut(address indexed operator, bytes[] pubkeys);

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    function initialize(address _owner) external;

    /// @notice Sets the AVS contracts in the registry
    /// @param gatewayAVSAddr Address of the GatewayAVS contract
    /// @param validatorAVSAddr Address of the ValidatorAVS contract
    function setAVSContracts(address gatewayAVSAddr, address validatorAVSAddr) external;

    /// @notice Registers a new operator
    /// @param operatorAddress The operator's address
    /// @param serviceType The type of service
    /// @param blsKey The BLS public key for gateway operators
    function registerOperator(
        address operatorAddress,
        RestakingServiceType serviceType,
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
    /// @param delegatee Array of delegatee public keys
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

    /// @notice Gets the number of validators registered to an operator
    /// @param operator The address of the operator
    /// @return The number of validators registered to the operator
    function getValidatorCountForOperatorInAVS(address operator)
        external
        view
        returns (uint256);

    /// @notice Gets registered operator data
    /// @param operatorAddr The operator's address
    /// @return gatewayOp The operator's gateway data
    /// @return validatorOp The operator's validator data
    function getRegisteredOperator(address operatorAddr)
        external
        view
        returns (Operator memory gatewayOp, Operator memory validatorOp);

    /// @notice Returns active operators for a specific AVS
    /// @param avsAddress The address of the AVS
    /// @return Array of operator addresses
    function getActiveOperatorsForAVS(address avsAddress)
        external
        view
        returns (address[] memory);

    /// @notice Returns the total validator count for a specific AVS
    /// @param avsAddress The address of the AVS
    /// @return The total count of validators
    function getTotalValidatorCountForAVS(address avsAddress)
        external
        view
        returns (uint256);

    /// @notice Get the service type of an AVS contract
    /// @param avsAddress The AVS contract address
    /// @return The service type of the AVS
    function getAvsType(address avsAddress)
        external
        view
        returns (RestakingServiceType);

    /// @notice Check if an operator is registered in the AVS
    /// @param operatorAddress The operator's address
    /// @param serviceType The type of service to check
    /// @return bool True if registered in the AVS
    function isOperatorRegisteredInAVS(
        address operatorAddress,
        RestakingServiceType serviceType
    )
        external
        view
        returns (bool);

    /// @notice The cooldown period required before completing opt-out
    function OPT_OUT_COOLDOWN() external view returns (uint256);

    /// @notice Update an operator's BLS key (only for gateway operators)
    /// @param operator The operator's address
    /// @param newBlsKey The new BLS public key
    function updateOperatorBLSKey(address operator, bytes calldata newBlsKey) external;

    /// @notice Gets the GatewayAVS contract instance
    /// @return The GatewayAVS contract instance
    function getGatewayAVS() external view returns (IGatewayAVS);

    /// @notice Gets the ValidatorAVS contract instance
    /// @return The ValidatorAVS contract instance
    function getValidatorAVS() external view returns (IValidatorAVS);

    /// @notice Returns the operator's public key and other info for a specific AVS type
    /// @param operator The operator's address
    /// @param avsType The type of AVS to get info for
    /// @return pubKey The operator's public key for the AVS type
    /// @return isActive Whether the operator is active
    function operatorInfo(
        address operator,
        RestakingServiceType avsType
    )
        external
        view
        returns (bytes memory pubKey, bool isActive);
}
