// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { GatewayAVS } from "./eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "./eigenlayer-avs/ValidatorAVS.sol";
import { IGatewayAVS } from "./interfaces/IGatewayAVS.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { IValidatorAVS } from "./interfaces/IValidatorAVS.sol";
import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";

import { EigenLayerOperatorManagement } from "./libs/EigenLayerOperatorManagement.sol";
import { SymbioticOperatorManagement } from "./libs/SymbioticOperatorManagement.sol";
import { ValidatorManagement } from "./libs/ValidatorManagement.sol";
import { TaiyiProposerRegistryStorage } from "./storage/TaiyiProposerRegistryStorage.sol";

import { SymbioticNetworkMiddleware } from
    "./symbiotic-network/SymbioticNetworkMiddleware.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { EnumerableMap } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title TaiyiProposerRegistry
/// @notice Registry contract for managing validators and operators in the Taiyi protocol
contract TaiyiProposerRegistry is
    IProposerRegistry,
    BLSSignatureChecker,
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    TaiyiProposerRegistryStorage
{
    using BLS12381 for BLS12381.G1Point;
    using ValidatorManagement for ValidatorManagement.ValidatorState;
    using
    EigenLayerOperatorManagement
    for EigenLayerOperatorManagement.EigenLayerOperatorState;
    using
    SymbioticOperatorManagement
    for SymbioticOperatorManagement.SymbioticOperatorState;
    using EnumerableSet for EnumerableSet.AddressSet;
    using Subnetwork for address;
    using Subnetwork for bytes32;

    /// @notice Error thrown when trying to deregister an operator with active validators
    error CannotDeregisterActiveValidator();

    /// @notice Error thrown when trying to deregister an operator with validators not opted out
    error CannotDeregisterNotOptedOut();

    /// @notice Error thrown when trying to deregister during cooldown period
    error CannotDeregisterInCooldown();

    /// @notice Error thrown when trying to update key for non-registered operator
    error OperatorNotRegistered();

    /// @notice Error thrown when trying to set an invalid AVS address
    error InvalidAVSAddress();

    /// @notice Error thrown when trying to set an invalid network address
    error InvalidNetworkAddress();

    /// @notice Error thrown when trying to update key for non-registered operator
    error NotAuthorized();

    // ============ External Functions ============

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    function initialize(address _owner) external initializer {
        _initialize(_owner);
    }

    /// @notice Sets the AVS contracts in the registry
    /// @param gatewayAVSAddr Address of the GatewayAVS contract
    /// @param validatorAVSAddr Address of the ValidatorAVS contract
    function setAVSContracts(
        address gatewayAVSAddr,
        address validatorAVSAddr
    )
        external
        onlyOwner
    {
        if (gatewayAVSAddr == address(0) || validatorAVSAddr == address(0)) {
            revert InvalidAVSAddress();
        }
        _gatewayAVSAddress = gatewayAVSAddr;
        _validatorAVSAddress = validatorAVSAddr;

        _avsTypes[gatewayAVSAddr] = RestakingServiceType.EIGENLAYER_GATEWAY;
        _avsTypes[validatorAVSAddr] = RestakingServiceType.EIGENLAYER_VALIDATOR;
    }

    /// @notice Sets the Symbiotic network contracts in the registry
    /// @param symbioticMiddlewareAddr Address of the Symbiotic middleware contract
    function setNetworkContracts(address symbioticMiddlewareAddr) external onlyOwner {
        if (symbioticMiddlewareAddr == address(0)) {
            revert InvalidNetworkAddress();
        }
        _symbioticMiddlewareAddress = symbioticMiddlewareAddr;
        _gatewaySubnetwork = symbioticMiddlewareAddr.subnetwork(1);
        _validatorSubnetwork = symbioticMiddlewareAddr.subnetwork(2);
    }

    /// @notice Register an operator for a specific service type
    /// @param operatorAddress The operator's address
    /// @param serviceType The type of service
    /// @param blsKey The BLS public key for gateway operators
    function registerOperator(
        address operatorAddress,
        RestakingServiceType serviceType,
        bytes calldata blsKey
    )
        external
        override
    {
        _registerOperator(operatorAddress, serviceType, blsKey);
    }

    /// @notice Deregisters an existing operator
    /// @param operatorAddress The address of the operator to deregister
    function deregisterOperator(address operatorAddress) external {
        _deregisterOperator(operatorAddress);
    }

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
        payable
    {
        _registerValidator(pubkey, operator, delegatee);
    }

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
        payable
    {
        require(pubkeys.length == delegatee.length, "Array length mismatch");
        for (uint256 i = 0; i < pubkeys.length; i++) {
            _registerValidator(pubkeys[i], operator, delegatee[i]);
        }
    }

    /// @notice Initiates the opt-out process for a validator
    /// @param pubKeyHash The hash of the validator's BLS public key
    /// @param signatureExpiry The expiry time of the signature
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry) external {
        _initOptOut(pubKeyHash, signatureExpiry);
    }

    /// @notice Confirms validator opt-out after cooldown period
    /// @param pubKeyHash The hash of the validator's BLS public key
    function confirmOptOut(bytes32 pubKeyHash) external {
        _confirmOptOut(pubKeyHash);
    }

    /// @notice Update an operator's BLS key (only for gateway operators)
    /// @param operator The operator's address
    /// @param newBlsKey The new BLS public key
    function updateOperatorBLSKey(
        address operator,
        bytes calldata newBlsKey
    )
        external
        override
    {
        if (msg.sender != operator && msg.sender != owner()) revert NotAuthorized();

        if (
            !eigenLayerOperatorState.isRegistered(
                operator, RestakingServiceType.EIGENLAYER_GATEWAY
            )
        ) {
            revert("Only gateway operators can update BLS keys");
        }

        (Operator memory gatewayOp,) = eigenLayerOperatorState.getOperatorData(operator);
        bytes memory oldKey = gatewayOp.blsKey;
        eigenLayerOperatorState.updateOperatorBLSKey(operator, newBlsKey);
        emit OperatorBLSKeyUpdated(operator, oldKey, newBlsKey);
    }

    // ============ View Functions ============

    /// @notice Gets the GatewayAVS contract instance
    function getGatewayAVS() external view returns (IGatewayAVS) {
        return IGatewayAVS(_gatewayAVSAddress);
    }

    /// @notice Gets the ValidatorAVS contract instance
    function getValidatorAVS() external view returns (IValidatorAVS) {
        return IValidatorAVS(_validatorAVSAddress);
    }

    /// @notice Gets operator address for a validator
    function getOperator(bytes32 pubKeyHash) external view returns (address) {
        return validators[pubKeyHash].operator;
    }

    /// @notice Gets the operator address for a given validator public key
    function getValidatorOperator(bytes calldata pubkey)
        external
        view
        returns (address)
    {
        return validators[keccak256(pubkey)].operator;
    }

    /// @notice Gets validator status by public key hash
    function getValidatorStatus(bytes32 pubKeyHash)
        external
        view
        returns (ValidatorStatus)
    {
        return validatorState.getValidatorStatus(pubKeyHash);
    }

    function getOperatorData(address operatorAddress)
        external
        view
        returns (Operator memory gatewayOp, Operator memory validatorOp)
    {
        return eigenLayerOperatorState.getOperatorData(operatorAddress);
    }

    /// @notice Gets validator status by public key
    function getValidatorStatus(bytes calldata pubKey)
        external
        view
        returns (ValidatorStatus)
    {
        return validators[keccak256(pubKey)].status;
    }

    /// @notice Gets validator information by public key hash
    function getValidator(bytes32 pubKeyHash) external view returns (Validator memory) {
        return validatorState.getValidator(pubKeyHash);
    }

    /// @notice Gets the number of validators registered to an operator
    function getValidatorCountForOperatorInAVS(address operator)
        external
        view
        returns (uint256)
    {
        return validatorState.getOperatorValidators(operator).length;
    }

    function getValidatorsForOperator(address operator)
        external
        view
        returns (bytes[] memory)
    {
        return validatorState.getOperatorValidators(operator);
    }

    /// @notice Gets registered operator data
    function getRegisteredOperator(address operatorAddr)
        external
        view
        returns (Operator memory gatewayOp, Operator memory validatorOp)
    {
        return eigenLayerOperatorState.getOperatorData(operatorAddr);
    }

    /// @notice Returns active operators for a specific AVS
    function getActiveOperatorsForAVS(address avsAddress)
        external
        view
        returns (address[] memory)
    {
        return eigenLayerOperatorState.getActiveOperators(avsAddress);
    }

    /// @notice Returns active operators for a specific subnetwork
    function getActiveOperatorsForNetwork(bytes32 subnetwork)
        external
        view
        returns (address[] memory)
    {
        return symbioticOperatorState.getActiveOperators(subnetwork);
    }

    /// @notice Returns the total validator count for a specific AVS
    function getTotalValidatorCountForAVS(address avsAddress)
        external
        view
        returns (uint256)
    {
        return _getTotalValidatorCountForAVS(avsAddress);
    }

    /// @notice Get the service type of an AVS contract
    /// @param avsAddress The restaking service contract address
    /// @return The service type of the restaking service
    function getAvsType(address avsAddress)
        external
        view
        override
        returns (RestakingServiceType)
    {
        return _avsTypes[avsAddress];
    }

    /// @notice Check if an operator is registered for a specific service type
    /// @param operatorAddress The operator's address
    /// @param serviceType The type of service to check
    /// @return bool True if the operator is registered
    function isOperatorRegisteredInAVS(
        address operatorAddress,
        RestakingServiceType serviceType
    )
        external
        view
        returns (bool)
    {
        return _isOperatorRegisteredInAVS(operatorAddress, serviceType);
    }

    /// @notice Gets the cooldown period for validator opt-out
    function OPT_OUT_COOLDOWN() external pure returns (uint256) {
        return _OPT_OUT_COOLDOWN;
    }

    /// @notice Gets the GatewayAVS contract instance
    function gatewayAVS() external view override returns (IGatewayAVS) {
        return IGatewayAVS(_gatewayAVSAddress);
    }

    /// @notice Gets the ValidatorAVS contract instance
    function validatorAVS() external view override returns (IValidatorAVS) {
        return IValidatorAVS(_validatorAVSAddress);
    }

    /// @notice Returns the operator's public key and other info for a specific AVS type
    function operatorInfo(
        address operator,
        RestakingServiceType avsType
    )
        external
        view
        returns (bytes memory pubKey, bool isActive)
    {
        (Operator memory gatewayData, Operator memory validatorData) =
            this.getRegisteredOperator(operator);

        if (avsType == RestakingServiceType.EIGENLAYER_GATEWAY) {
            pubKey = gatewayData.blsKey;
            isActive = gatewayData.operatorAddress != address(0);
        } else {
            pubKey = validatorData.blsKey;
            isActive = validatorData.operatorAddress != address(0);
        }

        return (pubKey, isActive);
    }

    // ============ Internal Functions ============

    /// @dev Internal function to register an operator
    function _registerOperator(
        address operatorAddress,
        RestakingServiceType serviceType,
        bytes calldata blsKey
    )
        internal
    {
        require(
            msg.sender == _symbioticMiddlewareAddress || msg.sender == _gatewayAVSAddress
                || msg.sender == _validatorAVSAddress,
            "Unauthorized middleware"
        );

        bool isEigenLayer = (
            serviceType == RestakingServiceType.EIGENLAYER_GATEWAY
                || serviceType == RestakingServiceType.EIGENLAYER_VALIDATOR
        );

        bool isGateway = (
            serviceType == RestakingServiceType.EIGENLAYER_GATEWAY
                || serviceType == RestakingServiceType.SYMBIOTIC_GATEWAY
        );

        // Validate BLS key requirements for all operators
        if (isGateway) {
            require(blsKey.length > 0, "BLS key required for gateway operators");
        } else {
            require(blsKey.length == 0, "BLS key not allowed for validator operators");
        }

        // Register with appropriate operator management system
        if (isEigenLayer) {
            // EigenLayer operator registration
            if (isGateway) {
                eigenLayerOperatorState.registerGatewayOperator(
                    operatorAddress, blsKey, msg.sender
                );
            } else {
                eigenLayerOperatorState.registerValidatorOperator(
                    operatorAddress, msg.sender
                );
            }
        } else {
            // Symbiotic operator registration
            if (isGateway) {
                symbioticOperatorState.registerGatewayOperator(
                    operatorAddress, blsKey, msg.sender
                );
            } else {
                symbioticOperatorState.registerValidatorOperator(
                    operatorAddress, msg.sender
                );
            }
        }

        emit OperatorRegistered(operatorAddress, msg.sender, serviceType);
    }

    /// @dev Internal function to register a validator
    function _registerValidator(
        bytes calldata pubkey,
        address operator,
        bytes calldata delegatee
    )
        internal
    {
        // Determine protocol type based on caller
        bool isEigenLayer = msg.sender == _validatorAVSAddress;
        bool isSymbiotic = msg.sender == _symbioticMiddlewareAddress;
        require(isEigenLayer || isSymbiotic, "Only AVS contracts can register validators");

        // Get appropriate service type based on protocol
        RestakingServiceType serviceType = isEigenLayer
            ? RestakingServiceType.EIGENLAYER_VALIDATOR
            : RestakingServiceType.SYMBIOTIC_VALIDATOR;

        // Check if operator is registered with correct protocol and service type
        require(
            isEigenLayer
                ? _isOperatorRegisteredInAVS(operator, serviceType)
                : _isOperatorRegisteredInSymbiotic(operator, serviceType),
            "Operator not registered with correct service"
        );
        require(delegatee.length > 0, "Invalid delegatee");

        bytes32 pubkeyHash = validatorState.registerValidator(pubkey, operator, delegatee);
        emit ValidatorRegistered(pubkeyHash, operator);
    }

    /// @dev Internal function to deregister an operator
    /// @dev Flow:
    /// 1. Validates caller is an authorized AVS contract (Gateway, Validator or Symbiotic)
    /// 2. Determines service type based on caller:
    ///    - EigenLayer Gateway -> EIGENLAYER_GATEWAY
    ///    - EigenLayer Validator -> EIGENLAYER_VALIDATOR
    ///    - Symbiotic -> Checks if registered as SYMBIOTIC_GATEWAY or SYMBIOTIC_VALIDATOR
    /// 3. For validator operators (both EigenLayer and Symbiotic):
    ///    - Checks all validator pubkeys associated with operator
    ///    - Validates validators are not active or in cooldown
    ///    - Requires validators to be fully opted out
    ///    - Clears operator association with validators
    /// 4. For Symbiotic operators:
    ///    - Deregisters from Symbiotic operator state
    function _deregisterOperator(address operatorAddress) internal {
        bool isEigenGateway = msg.sender == _gatewayAVSAddress;
        bool isEigenValidator = msg.sender == _validatorAVSAddress;
        bool isSymbioticMiddleware = msg.sender == _symbioticMiddlewareAddress;

        require(
            isEigenGateway || isEigenValidator || isSymbioticMiddleware,
            "Only AVS contracts can deregister operators"
        );

        RestakingServiceType serviceType;
        if (isEigenGateway) {
            serviceType = RestakingServiceType.EIGENLAYER_GATEWAY;
        } else if (isEigenValidator) {
            serviceType = RestakingServiceType.EIGENLAYER_VALIDATOR;
        } else if (isSymbioticMiddleware) {
            if (
                _isOperatorRegisteredInSymbiotic(
                    operatorAddress, RestakingServiceType.SYMBIOTIC_GATEWAY
                )
            ) {
                serviceType = RestakingServiceType.SYMBIOTIC_GATEWAY;
            } else if (
                _isOperatorRegisteredInSymbiotic(
                    operatorAddress, RestakingServiceType.SYMBIOTIC_VALIDATOR
                )
            ) {
                serviceType = RestakingServiceType.SYMBIOTIC_VALIDATOR;
            }
        }

        if (
            serviceType == RestakingServiceType.EIGENLAYER_VALIDATOR
                || serviceType == RestakingServiceType.SYMBIOTIC_VALIDATOR
        ) {
            bytes[] memory pubkeys = validatorState.getOperatorValidators(operatorAddress);
            for (uint256 i = 0; i < pubkeys.length; i++) {
                bytes32 pubkeyHash = keccak256(pubkeys[i]);
                ValidatorStatus status = validatorState.getValidatorStatus(pubkeyHash);

                if (status == ValidatorStatus.Active) {
                    revert CannotDeregisterActiveValidator();
                }
                if (status == ValidatorStatus.OptingOut) {
                    revert CannotDeregisterInCooldown();
                }
                if (status != ValidatorStatus.OptedOut) {
                    revert CannotDeregisterNotOptedOut();
                }
            }
            validatorState.clearOperatorForValidator(operatorAddress);
        }

        if (isSymbioticMiddleware) {
            symbioticOperatorState.deregisterOperator(
                operatorAddress, serviceType, msg.sender
            );
        } else {
            eigenLayerOperatorState.deregisterOperator(
                operatorAddress, serviceType, msg.sender
            );
        }
        emit OperatorDeregistered(operatorAddress, msg.sender);
    }

    /// @dev Internal function to get total validator count for an restaking service
    function _getTotalValidatorCountForAVS(address avsAddress)
        internal
        view
        returns (uint256)
    {
        uint256 totalCount = 0;
        address[] memory operators =
            eigenLayerOperatorState.getActiveOperators(avsAddress);
        for (uint256 i = 0; i < operators.length; i++) {
            totalCount += validatorState.getOperatorValidators(operators[i]).length;
        }
        return totalCount;
    }

    /// @dev Internal function to initialize the contract
    function _initialize(address _owner) internal {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    /// @dev Internal function to confirm validator opt-out
    function _confirmOptOut(bytes32 pubKeyHash) internal {
        validatorState.confirmOptOut(pubKeyHash);
    }

    /// @dev Internal function to check if an operator is registered in the AVS
    function _isOperatorRegisteredInAVS(
        address operatorAddress,
        RestakingServiceType serviceType
    )
        internal
        view
        returns (bool)
    {
        return eigenLayerOperatorState.isRegistered(operatorAddress, serviceType);
    }

    /// @dev Internal function to check if an operator is registered in the Symbiotic network
    function _isOperatorRegisteredInSymbiotic(
        address operatorAddress,
        RestakingServiceType serviceType
    )
        internal
        view
        returns (bool)
    {
        return symbioticOperatorState.isRegistered(operatorAddress, serviceType);
    }

    /// @dev Internal function to validate opt-out cooldown
    function _validateOptOutCooldown(bytes32 pubKeyHash) internal view {
        require(
            block.timestamp >= validators[pubKeyHash].optOutTimestamp + _OPT_OUT_COOLDOWN,
            "Opt-out cooldown period not elapsed"
        );
    }

    /// @dev Internal function to validate opt-out timestamp
    function _validateOptOutTimestamp(bytes32 pubkeyHash) internal view {
        require(
            block.timestamp < validators[pubkeyHash].optOutTimestamp + _OPT_OUT_COOLDOWN
                || validators[pubkeyHash].optOutTimestamp == 0,
            "Validator in opt-out cooldown period"
        );
    }

    /// @dev Internal function to initiate validator opt-out
    function _initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry) internal {
        require(
            msg.sender == _validatorAVSAddress, "Only ValidatorAVS can initiate opt-out"
        );

        validatorState.initOptOut(pubKeyHash, signatureExpiry);
    }

    /// @dev Function to authorize upgrades, only callable by owner
    function _authorizeUpgrade(address) internal override onlyOwner { }
}
