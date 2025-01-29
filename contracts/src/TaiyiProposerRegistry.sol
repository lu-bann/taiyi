// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TaiyiProposerRegistryStorage } from "./TaiyiProposerRegistryStorage.sol";
import { GatewayAVS } from "./eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "./eigenlayer-avs/ValidatorAVS.sol";
import { IGatewayAVS } from "./interfaces/IGatewayAVS.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { IValidatorAVS } from "./interfaces/IValidatorAVS.sol";
import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";
import { OperatorManagement } from "./libs/OperatorManagement.sol";
import { ValidatorManagement } from "./libs/ValidatorManagement.sol";
import { console } from "forge-std/console.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title TaiyiProposerRegistry
/// @notice Registry contract for managing validators and operators in the Taiyi protocol
/// @dev Follows the "internal-call" pattern seen in EigenLayerMiddleware
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
    using OperatorManagement for OperatorManagement.OperatorState;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev State variables
    ValidatorManagement.ValidatorState private validatorState;
    OperatorManagement.OperatorState private operatorState;

    /// @notice Error thrown when trying to deregister an operator with active validators
    error CannotDeregisterActiveValidator();

    /// @notice Error thrown when trying to deregister an operator with validators not opted out
    error CannotDeregisterNotOptedOut();

    /// @notice Error thrown when trying to deregister during cooldown period
    error CannotDeregisterInCooldown();

    /// @notice Emitted when validators are opted out
    event ValidatorsOptedOut(address indexed operator, bytes[] pubkeys);

    /// @notice Emitted when an operator is deregistered
    event OperatorDeregistered(address indexed operator, address indexed avsContract);

    // ============ External Functions ============

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
        _setAVSContracts(gatewayAVSAddr, validatorAVSAddr);
    }

    /// @notice Adds a new middleware contract to the registry
    /// @param middlewareContract Address of middleware contract to add
    function addRestakingMiddlewareContract(address middlewareContract)
        external
        onlyOwner
    {
        _addRestakingMiddlewareContract(middlewareContract);
    }

    /// @notice Removes a middleware contract from the registry
    /// @param middlewareContract Address of middleware contract to remove
    function removeRestakingMiddlewareContract(address middlewareContract)
        external
        onlyOwner
    {
        _removeRestakingMiddlewareContract(middlewareContract);
    }

    /// @notice Registers a new operator
    /// @param operatorAddress The address of the operator to register
    /// @param avsType The type of AVS (GATEWAY or VALIDATOR)
    /// @param blsKey The BLS public key for the operator (only for GATEWAY type)
    function registerOperator(
        address operatorAddress,
        AVSType avsType,
        bytes calldata blsKey
    )
        external
    {
        _registerOperator(operatorAddress, avsType, blsKey);
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
        _batchRegisterValidators(pubkeys, operator, delegatee);
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

    // ============ View Functions ============

    /// @notice Gets the GatewayAVS contract instance
    function getGatewayAVS() external view returns (IGatewayAVS) {
        return IGatewayAVS(address(_gatewayAVS));
    }

    /// @notice Gets the ValidatorAVS contract instance
    function getValidatorAVS() external view returns (IValidatorAVS) {
        return IValidatorAVS(address(_validatorAVS));
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

    /// @notice Gets registered operator data
    function getRegisteredOperator(address operatorAddr)
        external
        view
        returns (Operator memory gatewayOp, Operator memory validatorOp)
    {
        return operatorState.getOperatorData(operatorAddr);
    }

    /// @notice Returns active operators for a specific AVS type
    function getActiveOperatorsForAVS(address avs)
        external
        view
        returns (address[] memory)
    {
        return _avsToOperators[avs].values();
    }

    /// @notice Returns the total validator count for a specific AVS type
    function getTotalValidatorCountForAVS(address avs) external view returns (uint256) {
        return _getTotalValidatorCountForAVS(avs);
    }

    /// @notice Returns the AVS type for a given AVS address
    function getAVSType(address avs) external view returns (AVSType) {
        return _avsTypes[avs];
    }

    /// @notice Checks if an operator is registered in the AVS
    function isOperatorRegisteredInAVS(
        address operatorAddress,
        AVSType avsType
    )
        external
        view
        returns (bool)
    {
        return operatorState.isRegistered(operatorAddress, avsType);
    }

    /// @notice Sets the AVS type for a given AVS address
    function setAVSType(address avs, AVSType avsType) external onlyOwner {
        _setAVSType(avs, avsType);
    }

    /// @notice Checks if an operator is active in a specific AVS
    function isOperatorActiveInAVS(
        address avs,
        address operator
    )
        external
        view
        returns (bool)
    {
        return _avsToOperators[avs].contains(operator);
    }

    /// @notice Gets the cooldown period for validator opt-out
    function OPT_OUT_COOLDOWN() external pure returns (uint256) {
        return _OPT_OUT_COOLDOWN;
    }

    /// @notice Gets the GatewayAVS address
    function gatewayAVSAddress() external view returns (address) {
        return _gatewayAVSAddress;
    }

    /// @notice Gets the ValidatorAVS address
    function validatorAVSAddress() external view returns (address) {
        return _validatorAVSAddress;
    }

    /// @notice Gets the GatewayAVS contract instance
    function gatewayAVS() external view override returns (IGatewayAVS) {
        return IGatewayAVS(_gatewayAVSAddress);
    }

    /// @notice Gets the ValidatorAVS contract instance
    function validatorAVS() external view override returns (IValidatorAVS) {
        return IValidatorAVS(_validatorAVSAddress);
    }

    // ============ Internal Functions ============

    /// @dev Internal function to initialize the contract
    function _initialize(address _owner) internal {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    /// @dev Internal function to set AVS contracts
    function _setAVSContracts(
        address gatewayAVSAddr,
        address validatorAVSAddr
    )
        internal
    {
        require(gatewayAVSAddr != address(0), "Invalid gateway AVS address");
        require(validatorAVSAddr != address(0), "Invalid validator AVS address");

        _gatewayAVS = GatewayAVS(gatewayAVSAddr);
        _validatorAVS = ValidatorAVS(validatorAVSAddr);
        _gatewayAVSAddress = gatewayAVSAddr;
        _validatorAVSAddress = validatorAVSAddr;
    }

    /// @dev Internal function to register an operator
    function _registerOperator(
        address operatorAddress,
        AVSType avsType,
        bytes calldata blsKey
    )
        internal
    {
        if (avsType == AVSType.GATEWAY) {
            _registerGatewayAVSOperator(operatorAddress, blsKey);
        } else {
            _registerValidatorAVSOperator(operatorAddress);
        }
    }

    /// @dev Internal function to register a Gateway AVS operator
    function _registerGatewayAVSOperator(
        address operatorAddress,
        bytes calldata blsKey
    )
        internal
    {
        require(msg.sender == _gatewayAVSAddress, "Unauthorized middleware");
        operatorState.registerGatewayOperator(operatorAddress, blsKey, msg.sender);
        _avsToOperators[msg.sender].add(operatorAddress);
    }

    /// @dev Internal function to register a Validator AVS operator
    function _registerValidatorAVSOperator(address operatorAddress) internal {
        require(msg.sender == _validatorAVSAddress, "Unauthorized middleware");
        operatorState.registerValidatorOperator(operatorAddress, msg.sender);
        _avsToOperators[msg.sender].add(operatorAddress);
    }

    /// @dev Internal function to add a middleware contract
    function _addRestakingMiddlewareContract(address middlewareContract) internal {
        require(
            !restakingMiddlewareContracts.contains(middlewareContract),
            "Middleware already registered"
        );
        restakingMiddlewareContracts.add(middlewareContract);
    }

    /// @dev Internal function to remove a middleware contract
    function _removeRestakingMiddlewareContract(address middlewareContract) internal {
        require(
            restakingMiddlewareContracts.contains(middlewareContract),
            "Middleware not registered"
        );
        restakingMiddlewareContracts.remove(middlewareContract);
    }

    /// @dev Internal function to register a validator
    function _registerValidator(
        bytes calldata pubkey,
        address operator,
        bytes calldata delegatee
    )
        internal
    {
        require(
            msg.sender == _validatorAVSAddress,
            "Only ValidatorAVS can register validators"
        );
        require(
            _isOperatorRegisteredInAVS(operator, AVSType.VALIDATOR),
            "Operator not registered with VALIDATOR AVS"
        );
        require(delegatee.length > 0, "Invalid delegatee");

        bytes32 pubkeyHash = validatorState.registerValidator(pubkey, operator, delegatee);
        emit ValidatorRegistered(pubkeyHash, operator);
    }

    /// @dev Internal function to register multiple validators
    function _batchRegisterValidators(
        bytes[] calldata pubkeys,
        address operator,
        bytes[] calldata delegatees
    )
        internal
    {
        require(pubkeys.length == delegatees.length, "Array length mismatch");
        for (uint256 i = 0; i < pubkeys.length; i++) {
            _registerValidator(pubkeys[i], operator, delegatees[i]);
        }
    }

    /// @dev Internal function to initiate validator opt-out
    function _initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry) internal {
        require(
            msg.sender == _validatorAVSAddress, "Only ValidatorAVS can initiate opt-out"
        );

        validatorState.initOptOut(pubKeyHash, signatureExpiry);
    }

    /// @dev Internal function to confirm validator opt-out
    function _confirmOptOut(bytes32 pubKeyHash) internal {
        validatorState.confirmOptOut(pubKeyHash);
    }

    /// @dev Internal function to deregister an operator
    function _deregisterOperator(address operatorAddress) internal {
        require(
            msg.sender == _gatewayAVSAddress || msg.sender == _validatorAVSAddress,
            "Only AVS contracts can deregister operators"
        );

        AVSType avsType =
            msg.sender == _gatewayAVSAddress ? AVSType.GATEWAY : AVSType.VALIDATOR;

        // Check for active validators if deregistering from Validator AVS
        if (avsType == AVSType.VALIDATOR) {
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

        operatorState.deregisterOperator(operatorAddress, avsType, msg.sender);
        _avsToOperators[msg.sender].remove(operatorAddress);
        emit OperatorDeregistered(operatorAddress, msg.sender);
    }

    /// @dev Internal function to get total validator count for an AVS
    function _getTotalValidatorCountForAVS(address avs) internal view returns (uint256) {
        uint256 totalCount = 0;
        address[] memory operators = _avsToOperators[avs].values();
        for (uint256 i = 0; i < operators.length; i++) {
            totalCount += validatorState.getOperatorValidators(operators[i]).length;
        }
        return totalCount;
    }

    /// @dev Internal function to set AVS type
    function _setAVSType(address avs, AVSType avsType) internal {
        _avsTypes[avs] = avsType;
    }

    /// @dev Internal function to check if an operator is registered in the AVS
    function _isOperatorRegisteredInAVS(
        address operatorAddress,
        AVSType avsType
    )
        internal
        view
        returns (bool)
    {
        return operatorState.isRegistered(operatorAddress, avsType);
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

    /// @dev Function to authorize upgrades, only callable by owner
    function _authorizeUpgrade(address) internal override onlyOwner { }
}
