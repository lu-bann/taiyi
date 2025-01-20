// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title TaiyiProposerRegistry
 * @notice Registry contract for managing validators and operators in the Taiyi
 * protocol, rewritten to follow
 *         the "internal-call" pattern seen in EigenLayerMiddleware.
 */
contract TaiyiProposerRegistry is
    IProposerRegistry,
    BLSSignatureChecker,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    using BLS12381 for BLS12381.G1Point;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// ----------------------------------------------------------
    ///                      STATE
    /// ----------------------------------------------------------

    /// @notice Duration required for validators to complete opt-out process
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;

    // Maps each operator => which AVS they belong to => validator count
    mapping(address => mapping(address => uint256)) private _operatorToAVSValidatorCount;

    // Tracks the set of operators for each AVS
    mapping(address => EnumerableSet.AddressSet) private _avsToOperators;

    /// @notice Mapping from BLS public key hash to Validator structs
    mapping(bytes32 => Validator) public validators;

    /// @notice Mapping of operator addresses to their Operator structs
    mapping(address => Operator) public registeredOperators;

    /// @notice Set of middleware contracts authorized to call updating
    /// functions
    EnumerableSet.AddressSet private restakingMiddlewareContracts;

    /// ----------------------------------------------------------
    ///                INITIALIZER & UPGRADE LOGIC
    /// ----------------------------------------------------------

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    /// minimal example, but kept for compatibility)
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    /// ----------------------------------------------------------
    ///                        MODIFIERS
    /// ----------------------------------------------------------

    /// @notice Restricts function access to registered middleware contracts
    modifier onlyRestakingMiddlewareContracts() {
        require(
            restakingMiddlewareContracts.contains(msg.sender), "Unauthorized middleware"
        );
        _;
    }

    /// ----------------------------------------------------------
    ///                EXTERNAL STATE-CHANGING FUNCTIONS
    /// ----------------------------------------------------------

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
    function registerOperator(address operatorAddress) external {
        _registerOperator(operatorAddress);
    }

    /// @notice Deregisters an existing operator
    /// @param operatorAddress The address of the operator to deregister
    function deregisterOperator(address operatorAddress) external {
        _deregisterOperator(operatorAddress);
    }

    /// @notice Registers a single validator
    /// @param pubkey The BLS public key of the validator
    /// @param operator The operator address for the validator
    function registerValidator(
        bytes calldata pubkey,
        address operator
    )
        external
        payable
    {
        _registerValidator(pubkey, operator);
    }

    /// @notice Registers multiple validators in a single transaction
    /// @param pubkeys Array of BLS public keys
    /// @param operator The operator address for all validators
    function batchRegisterValidators(
        bytes[] calldata pubkeys,
        address operator
    )
        external
        payable
    {
        _batchRegisterValidators(pubkeys, operator);
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

    /// ----------------------------------------------------------
    ///                       INTERNAL FUNCTIONS
    /// ----------------------------------------------------------

    /// @notice Hashes a BLS public key
    /// @param pubkey The BLS public key to hash
    /// @return The hash of the public key
    function _hashBLSPubKey(bytes calldata pubkey) internal pure returns (bytes32) {
        return keccak256(pubkey);
    }

    /// @dev Internal function that adds a new middleware contract to the
    /// registry
    function _addRestakingMiddlewareContract(address middlewareContract) internal {
        restakingMiddlewareContracts.add(middlewareContract);
    }

    /// @dev Internal function that removes a middleware contract from the
    /// registry
    function _removeRestakingMiddlewareContract(address middlewareContract) internal {
        restakingMiddlewareContracts.remove(middlewareContract);
    }

    /// @dev Internal function that registers a new operator
    function _registerOperator(
        address operatorAddress,
        address middlewareContract
    )
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operatorAddress].operatorAddress == address(0),
            "Operator already registered"
        );

        Operator memory operatorData = Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: msg.sender
        });

        registeredOperators[operatorAddress] = operatorData;

        _avsToOperators[msg.sender].add(operatorAddress);
    }

    /// @dev Internal function that deregisters an existing operator
    function _deregisterOperator(address operatorAddress)
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operatorAddress].operatorAddress != address(0),
            "Operator not registered"
        );

        _avsToOperators[msg.sender].remove(operatorAddress);

        delete registeredOperators[operatorAddress];
    }

    /// @dev Internal function that registers a single validator
    function _registerValidator(
        bytes calldata pubkey,
        address operator
    )
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operator].operatorAddress != address(0),
            "Operator not registered"
        );

        bytes32 pubkeyHash = keccak256(pubkey);
        require(
            validators[pubkeyHash].status == ValidatorStatus.NotRegistered,
            "Validator already registered"
        );

        validators[pubkeyHash] = Validator({
            pubkey: pubkey,
            operator: operator,
            status: ValidatorStatus.Active,
            optOutTimestamp: 0
        });

        address avs = registeredOperators[operator].restakingMiddlewareContract;
        require(avs == msg.sender, "Unauthorized middleware");
        require(avs != address(0), "AVS not registered");
        _operatorToAVSValidatorCount[avs][operator] += 1;

        emit ValidatorRegistered(pubkeyHash, operator);
    }

    /// @dev Internal function that batch-registers multiple validators
    function _batchRegisterValidators(
        bytes[] calldata pubkeys,
        address operator
    )
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operator].operatorAddress != address(0),
            "Operator not registered"
        );

        for (uint256 i = 0; i < pubkeys.length; i++) {
            this.registerValidator(pubkeys[i], operator);
        }
    }

    /// @dev Internal function that initiates the opt-out process for a
    /// validator
    function _initOptOut(
        bytes32 pubKeyHash,
        uint256 signatureExpiry
    )
        //BLS12381.G2Point calldata signature
        internal
    {
        Validator storage validator = validators[pubKeyHash];

        require(validator.operator != address(0), "Validator not registered");
        require(validator.status == ValidatorStatus.Active, "Invalid status");
        require(block.timestamp <= signatureExpiry, "Signature expired");

        /// If you have actual BLS signature verification, uncomment:
        /// bytes memory message = abi.encodePacked(pubKeyHash,
        /// signatureExpiry);
        /// require(BLS12381.verifySignature(validator.pubkey, message,
        /// signature), "Invalid signature");

        validator.status = ValidatorStatus.OptingOut;
        validator.optOutTimestamp = block.timestamp;

        emit ValidatorStatusChanged(pubKeyHash, ValidatorStatus.OptingOut);
    }

    /// @dev Internal function that confirms validator opt-out after cooldown
    /// period
    function _confirmOptOut(bytes32 pubKeyHash) internal {
        Validator storage validator = validators[pubKeyHash];
        require(validator.operator != address(0), "Validator not registered");
        require(validator.status == ValidatorStatus.OptingOut, "Validator not opting out");
        require(
            block.timestamp >= validator.optOutTimestamp + OPT_OUT_COOLDOWN,
            "Cooldown period not elapsed"
        );
        require(
            block.timestamp >= validator.optOutTimestamp + OPT_OUT_COOLDOWN,
            "Cooldown period not elapsed"
        );

        validator.status = ValidatorStatus.OptedOut;
        validator.operator = address(0);
        validator.optOutTimestamp = 0;

        emit ValidatorOptedOut(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ValidatorStatus.OptedOut);
    }

    /// ----------------------------------------------------------
    ///                          VIEW
    /// ----------------------------------------------------------

    /// @notice Gets the operator address for a given validator public key
    /// @param pubkey The BLS public key of the validator
    /// @return The operator address associated with the validator
    function getValidatorOperator(bytes calldata pubkey)
        external
        view
        returns (address)
    {
        bytes32 pubKeyHash = keccak256(pubkey);
        Validator memory validator = validators[pubKeyHash];
        require(validator.operator != address(0), "Validator not registered");
        return validator.operator;
    }

    /// @notice Checks if an operator is registered in the registry
    /// @param operatorAddress The address of the operator to check
    /// @return bool True if the operator is registered, false otherwise
    function isOperatorRegistered(address operatorAddress) public view returns (bool) {
        return
            registeredOperators[operatorAddress].restakingMiddlewareContract != address(0);
    }

    /// @notice Gets validator status by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes32 pubKeyHash)
        external
        view
        returns (ValidatorStatus)
    {
        return validators[pubKeyHash].status;
    }

    /// @notice Gets validator status by public key
    /// @param pubKey The validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes calldata pubKey)
        external
        view
        returns (ValidatorStatus)
    {
        return validators[_hashBLSPubKey(pubKey)].status;
    }

    /// @notice Gets validator information by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's information
    function getValidator(bytes32 pubKeyHash) public view returns (Validator memory) {
        return validators[pubKeyHash];
    }

    /// @notice Gets operator address for a validator
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The operator's address
    function getOperator(bytes32 pubKeyHash) public view returns (address) {
        return validators[pubKeyHash].operator;
    }

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
        override
        returns (uint256)
    {
        return _operatorToAVSValidatorCount[avs][operator];
    }

    /// @notice Gets all active operators registered with a specific AVS
    /// @param avs The address of the AVS contract
    /// @return An array of operator addresses registered with the AVS
    function getActiveOperatorsForAVS(address avs)
        external
        view
        override
        returns (address[] memory)
    {
        uint256 length = _avsToOperators[avs].length();
        address[] memory results = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            results[i] = _avsToOperators[avs].at(i);
        }
        return results;
    }

    /// @notice Gets the total number of validators registered across all operators for an AVS
    /// @param avs The address of the AVS contract
    /// @return The total number of validators registered with the AVS
    function getTotalValidatorCountForAVS(address avs)
        external
        view
        override
        returns (uint256)
    {
        uint256 totalCount = 0;
        uint256 length = _avsToOperators[avs].length();
        for (uint256 i = 0; i < length; i++) {
            address op = _avsToOperators[avs].at(i);
            totalCount += _operatorToAVSValidatorCount[avs][op];
        }
        return totalCount;
    }
}
