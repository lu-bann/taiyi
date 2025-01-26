// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { GatewayAVS } from "./eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "./eigenlayer-avs/ValidatorAVS.sol";
import { IGatewayAVS } from "./interfaces/IGatewayAVS.sol";

import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { IValidatorAVS } from "./interfaces/IValidatorAVS.sol";
import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
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
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    using BLS12381 for BLS12381.G1Point;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Error thrown when trying to deregister an operator with active validators
    error CannotDeregisterActiveValidator();

    /// @notice Error thrown when trying to deregister an operator with validators in cooldown
    error CannotDeregisterInCooldown();

    /// @notice Error thrown when trying to deregister an operator with pending opt-out validators
    error CannotDeregisterPendingOptOut();

    /// @notice Error thrown when trying to deregister an operator with validators not opted out
    error CannotDeregisterNotOptedOut();

    /// @notice Emitted when an operator is deregistered from the registry
    /// @param operatorAddress The address of the deregistered operator
    /// @param avsAddress The address of the AVS contract that deregistered the operator
    event OperatorDeregistered(
        address indexed operatorAddress, address indexed avsAddress
    );

    /// @notice Emitted when validators are opted out during operator deregistration
    /// @param operatorAddress The address of the operator whose validators were opted out
    /// @param pubkeys The BLS public keys of the opted out validators
    event ValidatorsOptedOut(address indexed operatorAddress, bytes[] pubkeys);

    /// @notice Emitted when an operator is registered with the registry
    /// @param operatorAddress The address of the registered operator
    /// @param avsAddress The address of the AVS contract that registered the operator
    /// @param pubKeys The BLS public keys of the registered operator
    event OperatorRegistered(
        address indexed operatorAddress, address indexed avsAddress, bytes pubKeys
    );

    /// ----------------------------------------------------------
    ///                      STATE
    /// ----------------------------------------------------------

    /// @notice Duration required for validators to complete opt-out process
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;

    /// @notice Mapping from operator BLS public key to their operator data
    mapping(bytes => Operator) public operatorBlsKeyToData;

    /// @dev Maps operator address to array of their validator pubkey hashes
    mapping(address => bytes32[]) public operatorToValidatorPubkeys;

    /// @dev Mapping AVS => AVSType, so we know how to categorize operators
    mapping(address => AVSType) private _avsTypes;

    // Tracks the set of operators for each AVS
    mapping(address => EnumerableSet.AddressSet) private _avsToOperators;

    /// @notice Mapping from BLS public key hash to Validator structs
    mapping(bytes32 => Validator) public validators;

    /// @notice Mapping of operator addresses to their Operator structs
    mapping(address => mapping(AVSType => Operator)) public registeredOperators;

    /// @notice Set of middleware contracts authorized to call updating
    /// functions
    EnumerableSet.AddressSet private restakingMiddlewareContracts;

    /// @notice GatewayAVS contract instance
    GatewayAVS private _gatewayAVS;

    /// @notice ValidatorAVS contract instance
    ValidatorAVS private _validatorAVS;

    /// @notice GatewayAVS address
    address public override gatewayAVSAddress;

    /// @notice ValidatorAVS address
    address public override validatorAVSAddress;

    /// ----------------------------------------------------------
    ///                INITIALIZER & UPGRADE LOGIC
    /// ----------------------------------------------------------

    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    /// minimal example, but kept for compatibility)
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
        external
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();

        _gatewayAVS = new GatewayAVS();
        _validatorAVS = new ValidatorAVS();

        // Initialize the AVS contracts
        _gatewayAVS.initialize(
            _owner,
            address(this),
            _aveDirectory,
            _delegationManager,
            _strategyManager,
            _eigenPodManager,
            _rewardCoordinator,
            _rewardInitiator,
            _gatewayShareBips
        );

        _validatorAVS.initialize(
            _owner,
            address(this),
            _aveDirectory,
            _delegationManager,
            _strategyManager,
            _eigenPodManager,
            _rewardCoordinator,
            _rewardInitiator,
            _gatewayShareBips
        );

        gatewayAVSAddress = address(_gatewayAVS);
        validatorAVSAddress = address(_validatorAVS);

        addRestakingMiddlewareContract(address(_gatewayAVS));
        addRestakingMiddlewareContract(address(_validatorAVS));

        _avsTypes[address(_gatewayAVS)] = AVSType.GATEWAY;
        _avsTypes[address(_validatorAVS)] = AVSType.VALIDATOR;
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

    /// @notice Restricts function access to only the ValidatorAVS contract
    modifier onlyValidatorAVS() {
        require(msg.sender == validatorAVSAddress, "Only ValidatorAVS can call");
        _;
    }

    /// ----------------------------------------------------------
    ///                EXTERNAL STATE-CHANGING FUNCTIONS
    /// ----------------------------------------------------------

    /// @notice Adds a new middleware contract to the registry
    /// @param middlewareContract Address of middleware contract to add
    function addRestakingMiddlewareContract(address middlewareContract)
        public
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
    function registerOperator(
        address operatorAddress,
        AVSType avsType,
        bytes calldata blsKey
    )
        external
    {
        if (avsType == AVSType.GATEWAY) {
            _registerGatewayAVSOperator(operatorAddress, blsKey);
        } else {
            _registerValidatorAVSOperator(operatorAddress);
        }
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
    /// @dev Only callable by the ValidatorAVS contract
    /// @param pubKeyHash The hash of the validator's BLS public key
    /// @param signatureExpiry The expiry time of the signature
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry) external {
        _initOptOut(pubKeyHash, signatureExpiry, IProposerRegistry.AVSType.VALIDATOR);
    }

    /// @notice Confirms validator opt-out after cooldown period
    /// @param pubKeyHash The hash of the validator's BLS public key
    function confirmOptOut(bytes32 pubKeyHash) external {
        _confirmOptOut(pubKeyHash);
    }

    /// ----------------------------------------------------------
    ///                       INTERNAL FUNCTIONS
    /// ----------------------------------------------------------

    /// @dev Let owner manually set AVSType for any AVS
    function setAVSType(address avs, AVSType avsType) external onlyOwner {
        _avsTypes[avs] = avsType;
    }

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

    function _registerValidatorAVSOperator(address operatorAddress)
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operatorAddress][AVSType.VALIDATOR].operatorAddress
                == address(0),
            "Operator already registered"
        );

        Operator memory operatorData = Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: msg.sender,
            avsType: AVSType.VALIDATOR,
            blsKey: bytes("")
        });

        registeredOperators[operatorAddress][AVSType.VALIDATOR] = operatorData;
        _avsToOperators[msg.sender].add(operatorAddress);
    }

    /// @dev Internal function that registers a new operator
    function _registerGatewayAVSOperator(
        address operatorAddress,
        bytes calldata pubKeys
    )
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operatorAddress][AVSType.GATEWAY].operatorAddress
                == address(0),
            "Operator already registered"
        );

        Operator memory operatorData = Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: msg.sender,
            avsType: AVSType.GATEWAY,
            blsKey: pubKeys
        });

        registeredOperators[operatorAddress][AVSType.GATEWAY] = operatorData;
        _avsToOperators[msg.sender].add(operatorAddress);
        operatorBlsKeyToData[pubKeys] = operatorData;
        emit OperatorRegistered(operatorAddress, msg.sender, pubKeys);
    }

    /// @notice Internal function to deregister an operator from the registry
    /// @dev This function can only be called by authorized middleware contracts
    /// @dev Checks that all validators associated with operator are either opted out or past cooldown
    /// @dev Removes operator from AVS mapping and deletes their registration record
    /// @param operatorAddress The address of the operator to deregister
    function _deregisterOperator(address operatorAddress)
        internal
        onlyRestakingMiddlewareContracts
    {
        AVSType avsType = getAVSType(msg.sender);
        require(
            registeredOperators[operatorAddress][avsType].operatorAddress != address(0),
            "Operator not registered"
        );

        if (avsType == AVSType.VALIDATOR) {
            // For ValidatorAVS, we need to check and handle all associated validators
            bytes32[] memory operatorValidatorPubkeys =
                operatorToValidatorPubkeys[operatorAddress];
            bytes[] memory optedOutPubkeys = new bytes[](operatorValidatorPubkeys.length);
            uint256 optedOutCount = 0;

            for (uint256 i = 0; i < operatorValidatorPubkeys.length; i++) {
                bytes32 pubkeyHash = operatorValidatorPubkeys[i];
                Validator storage val = validators[pubkeyHash];

                ValidatorStatus status = val.status;
                if (status == ValidatorStatus.Active) {
                    revert CannotDeregisterActiveValidator();
                }

                if (status == ValidatorStatus.OptingOut) {
                    if (block.timestamp < val.optOutTimestamp + OPT_OUT_COOLDOWN) {
                        revert CannotDeregisterInCooldown();
                    }
                    revert CannotDeregisterPendingOptOut();
                }

                if (status != ValidatorStatus.OptedOut) {
                    revert CannotDeregisterNotOptedOut();
                }

                optedOutPubkeys[optedOutCount] = val.pubkey;
                optedOutCount++;
            }

            // Clear operator's validator associations
            delete operatorToValidatorPubkeys[operatorAddress];

            // Emit ValidatorsOptedOut event only for ValidatorAVS
            emit ValidatorsOptedOut(operatorAddress, optedOutPubkeys);
        }

        // Common deregistration logic for both AVS types
        _avsToOperators[msg.sender].remove(operatorAddress);

        // If Gateway operator, clear BLS key mapping
        if (avsType == AVSType.GATEWAY) {
            bytes memory blsKey = registeredOperators[operatorAddress][avsType].blsKey;
            if (blsKey.length > 0) {
                delete operatorBlsKeyToData[blsKey];
            }
        }

        // Delete the operator's record
        delete registeredOperators[operatorAddress][avsType];

        // Emit deregistration event
        emit OperatorDeregistered(operatorAddress, msg.sender);
    }

    /// @dev Internal function that registers a single validator
    function _registerValidator(
        bytes calldata pubkey,
        address operator,
        bytes calldata delegatee
    )
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operator][AVSType.VALIDATOR].operatorAddress != address(0),
            "Operator not registered with VALIDATOR AVS"
        );
        require(delegatee.length > 0, "Invalid delegatee");

        bytes32 pubkeyHash = keccak256(pubkey);
        require(
            validators[pubkeyHash].status == ValidatorStatus.NotRegistered,
            "Validator already registered"
        );

        validators[pubkeyHash] = Validator({
            pubkey: pubkey,
            operator: operator,
            status: ValidatorStatus.Active,
            optOutTimestamp: 0,
            delegatee: delegatee
        });

        address avs =
            registeredOperators[operator][AVSType.VALIDATOR].restakingMiddlewareContract;
        require(avs == msg.sender, "Unauthorized middleware");

        operatorToValidatorPubkeys[operator].push(pubkeyHash);

        emit ValidatorRegistered(pubkeyHash, operator);
    }

    /// @dev Internal function that batch-registers multiple validators
    function _batchRegisterValidators(
        bytes[] calldata pubkeys,
        address operator,
        bytes[] calldata delegatee
    )
        internal
        onlyRestakingMiddlewareContracts
    {
        require(
            registeredOperators[operator][AVSType.VALIDATOR].operatorAddress != address(0),
            "Operator not registered with VALIDATOR AVS"
        );

        for (uint256 i = 0; i < pubkeys.length; i++) {
            _registerValidator(pubkeys[i], operator, delegatee[i]);
        }
    }

    /// @dev Internal function that initiates the opt-out process for a validator
    function _initOptOut(
        bytes32 pubKeyHash,
        uint256 signatureExpiry,
        AVSType avsType
    )
        internal
        onlyValidatorAVS
    {
        Validator storage validator = validators[pubKeyHash];

        // Get the operator from the validator struct
        address operator = validator.operator;

        // Get the middleware contract associated with the operator
        address operatorMiddleware =
            registeredOperators[operator][avsType].restakingMiddlewareContract;

        // Ensure the request is coming from the correct middleware contract
        require(
            msg.sender == operatorMiddleware,
            "Only the AVS middleware contract can initiate opt-out"
        );

        require(validator.status == ValidatorStatus.Active, "Invalid status");
        require(block.timestamp <= signatureExpiry, "Signature expired");

        // for actual BLS signature verification, uncomment:
        // bytes memory message = abi.encodePacked(pubKeyHash,
        // signatureExpiry);
        // require(BLS12381.verifySignature(validator.pubkey, message,
        // signature), "Invalid signature");

        validator.status = ValidatorStatus.OptingOut;
        validator.optOutTimestamp = block.timestamp;

        emit ValidatorStatusChanged(pubKeyHash, ValidatorStatus.OptingOut);
    }

    /// @dev Internal function that confirms validator opt-out after cooldown
    /// period
    function _confirmOptOut(bytes32 pubKeyHash) internal {
        Validator storage validator = validators[pubKeyHash];

        require(validator.operator != msg.sender, "Validator not registered");
        require(validator.status == ValidatorStatus.OptingOut, "Validator not opting out");
        require(
            block.timestamp >= validator.optOutTimestamp + OPT_OUT_COOLDOWN,
            "Cooldown period not elapsed"
        );

        validator.status = ValidatorStatus.OptedOut;

        emit ValidatorOptedOut(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ValidatorStatus.OptedOut);
    }

    /// ----------------------------------------------------------
    ///                          VIEW
    /// ----------------------------------------------------------

    /// @dev Returns the AVSType for a given AVS
    function getAVSType(address avs) public view returns (AVSType) {
        return _avsTypes[avs];
    }

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
        returns (bool)
    {
        return _avsToOperators[avs].contains(operator);
    }

    /// @notice Checks if an operator is registered in an AVS given the operator address and the AVSType
    /// @param operatorAddress The address of the operator to check
    /// @param avsType The type of AVS
    /// @return bool True if the operator is registered, false otherwise
    function isOperatorRegisteredInAVS(
        address operatorAddress,
        AVSType avsType
    )
        public
        view
        returns (bool)
    {
        return registeredOperators[operatorAddress][avsType].operatorAddress != address(0);
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
        // Check if operator is registered with the given AVS
        AVSType avsType = _avsTypes[avs];
        Operator memory op = registeredOperators[operator][avsType];
        if (op.restakingMiddlewareContract == avs) {
            return operatorToValidatorPubkeys[operator].length;
        } else {
            return 0;
        }
    }

    /// @notice New function that returns active operators specifically for
    ///         GATEWAY-type or VALIDATOR-type AVSs.
    /// @param avs The address of the AVS
    /// @param avsType The AVSType (GATEWAY or VALIDATOR)
    /// @return an array of operator addresses for that AVS
    function getActiveOperatorsForAVS(
        address avs,
        AVSType avsType
    )
        external
        view
        returns (address[] memory)
    {
        // only return operators if the AVSType matches
        require(_avsTypes[avs] == avsType, "Mismatched AVSType");
        uint256 length = _avsToOperators[avs].length();
        address[] memory results = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            results[i] = _avsToOperators[avs].at(i);
        }
        return results;
    }

    /// @notice Returns the total number of validators registered for a specific AVS
    /// @param avs The address of the AVS to check
    /// @return The total count of validators across all operators for this AVS
    /// @dev Iterates through all operators registered with this AVS and sums their validator counts
    function getTotalValidatorCountForAVS(
        address avs,
        AVSType avsType
    )
        external
        view
        returns (uint256)
    {
        // only return operators if the AVSType matches
        require(_avsTypes[avs] == avsType, "Mismatched AVSType");
        uint256 totalCount = 0;
        uint256 length = _avsToOperators[avs].length();
        for (uint256 i = 0; i < length; i++) {
            address op = _avsToOperators[avs].at(i);
            totalCount += operatorToValidatorPubkeys[op].length;
        }
        return totalCount;
    }

    /// @notice Gets the registered operator details for both GATEWAY and VALIDATOR AVS types
    /// @param operatorAddr The address of the operator to query
    /// @return A tuple containing two Operator structs - first for GATEWAY type, second for VALIDATOR type
    /// @dev Returns empty Operator structs if operator is not registered for either type
    function getRegisteredOperator(address operatorAddr)
        external
        view
        override
        returns (Operator memory, Operator memory)
    {
        return (
            registeredOperators[operatorAddr][AVSType.GATEWAY],
            registeredOperators[operatorAddr][AVSType.VALIDATOR]
        );
    }

    /// @notice Gets the GatewayAVS contract instance
    /// @return The GatewayAVS contract instance
    function gatewayAVS() external view override returns (IGatewayAVS) {
        return IGatewayAVS(gatewayAVSAddress);
    }

    /// @notice Gets the ValidatorAVS contract instance
    /// @return The ValidatorAVS contract instance
    function validatorAVS() external view override returns (IValidatorAVS) {
        return IValidatorAVS(validatorAVSAddress);
    }
}
