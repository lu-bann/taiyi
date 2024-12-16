// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";
import { EnumerableSet } from "open-zeppelin/utils/structs/EnumerableSet.sol";
import { OwnableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title TaiyiProposerRegistry
/// @notice Registry contract for managing validators and operators in the Taiyi protocol
/// @dev Implements validator registration, opt-out, and operator management functionality
contract TaiyiProposerRegistry is IProposerRegistry, BLSSignatureChecker, OwnableUpgradeable, UUPSUpgradeable {
    using BLS12381 for BLS12381.G1Point;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Mapping from BLS public key hash to Validator structs
    mapping(bytes32 => Validator) public validators;

    /// @notice Duration required for validators to complete opt-out process
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;

    /// @notice Mapping of operator addresses to their Operator structs
    mapping(address => Operator) public registeredOperators;

    EnumerableSet.AddressSet private restakingMiddlewareContracts;


    /// @notice Initializes the contract
    /// @param _owner Address of the contract owner
    /// @param _proposerRegistry Address of the proposer registry
    /// @param _avsDirectory Address of the AVS directory
    function initialize(address _owner, address _proposerRegistry, address _avsDirectory) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();

        transferOwnership(_owner);
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    /// @notice Restricts function access to registered middleware contracts
    modifier onlyRestakingMiddlewareContracts() {
        require(restakingMiddlewareContracts.contains(msg.sender), "Unauthorized middleware");
        _;
    }

    //////// REGISTRATION ////////

    /// @notice Adds a new middleware contract to the registry
    /// @param middlewareContract Address of middleware contract to add
    function addRestakingMiddlewareContract(address middlewareContract) external onlyOwner {
        restakingMiddlewareContracts.add(middlewareContract);
    }

    /// @notice Removes a middleware contract from the registry
    /// @param middlewareContract Address of middleware contract to remove
    function removeRestakingMiddlewareContract(address middlewareContract) external onlyOwner {
        restakingMiddlewareContracts.remove(middlewareContract);
    }

    /// @notice Gets the operator address for a given validator public key
    /// @param pubkey The BLS public key of the validator
    /// @return The operator address associated with the validator
    function getValidatorOperator(bytes calldata pubkey) external view returns (address) {
        bytes32 pubKeyHash = keccak256(pubkey);
        Validator memory validator = validators[pubKeyHash];
        require(validator.operator != address(0), "Validator not registered");
        return validator.operator;
    }

    /// @notice Registers a new operator
    /// @param operatorAddress The address of the operator to register
    /// @param rpcUrl The RPC URL of the operator
    /// @param middlewareContract The middleware contract address
    function registerOperator(
        address operatorAddress,
        string calldata rpcUrl,
        address middlewareContract
    )
        external
        onlyRestakingMiddlewareContracts
    {
        require(registeredOperators[operatorAddress].operatorAddress != address(0), "Operator already registered");

        //avsDirectory.registerOperatorToAVS(operator, operatorSignature);

        Operator memory operator = Operator({
            operatorAddress: operatorAddress,
            rpc: rpcUrl,
            restakingMiddlewareContract: middlewareContract
        });

        registeredOperators[operatorAddress] = operator;
    }

    /// @notice Deregisters an existing operator
    /// @param operatorAddress The address of the operator to deregister
    function deregisterOperator(address operatorAddress) onlyRestakingMiddlewareContracts external {
        require(registeredOperators[operatorAddress].operatorAddress != address(0), "Operator not registered");

        //avsDirectory.deregisterOperatorFromAVS(operator);

        delete registeredOperators[operatorAddress];
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
        onlyRestakingMiddlewareContracts
    {
        _registerValidator(pubkey, operator);
    }

    /// @notice Internal function to register a single validator
    /// @param pubkey The BLS public key of the validator
    /// @param operator The operator address for the validator
    function _registerValidator(bytes calldata pubkey, address operator) internal {
        require(registeredOperators[operator].operatorAddress != address(0), "Operator not registered");

        bytes32 pubkeyHash = keccak256(pubkey);

        require(validators[pubkeyHash].status == ValidatorStatus.NotRegistered, "Validator already registered");

        validators[pubkeyHash] =
            Validator({ pubkey: pubkey, operator: operator, status: ValidatorStatus.Active, optOutTimestamp: 0 });

        emit ValidatorRegistered(pubkeyHash, operator);
    }

    /**
     * @notice Registers a validator with the given BLS public key and stake
     * @param pubkey The BLS public key of the validator
     */
    // function _registerValidator(
    //     bytes calldata pubkey,
    //     // uint256 signatureExpiry,
    //     // BLS12381.G2Point calldata signature,
    //     address sender
    // )
    //     private
    // {
    // Construct message to sign
    // bytes memory message = abi.encodePacked(ProposerStatus.OptIn, signatureExpiry, msg.sender);

    // Verify BLS signature
    // require(block.timestamp <= signatureExpiry, "Signature expired");
    // require(BLSSignatureChecker.verifySignature(message, signature, pubkey), "Invalid BLS signature");

    //     require(registeredOperators[msg.sender], "Operator not registered");

    //     bytes32 pubKeyHash = _hashBLSPubKey(pubkey);
    //     require(validators[pubKeyHash].registrar == address(0), "Validator already registered");

    //     validators[pubKeyHash] =
    //         Validator({ pubkey: pubkey, registrar: msg.sender, status: ProposerStatus.OptIn, optOutTimestamp: 0 });

    //     emit ValidatorOptedIn(pubKeyHash, msg.sender);
    //     emit ValidatorStatusChanged(pubKeyHash, ProposerStatus.OptIn);
    // }

    /// @notice Internal function to register multiple validators
    /// @param pubkeys Array of BLS public keys
    /// @param operator The operator address for all validators
    function _registerValidators(bytes[] calldata pubkeys, address operator) internal {
        require(registeredOperators[operator].operatorAddress != address(0), "Operator not registered");

        for (uint256 i = 0; i < pubkeys.length; i++) {
            bytes memory pubkey = pubkeys[i];
            bytes32 pubkeyHash = keccak256(pubkey);

            require(validators[pubkeyHash].status == ValidatorStatus.NotRegistered, "Validator already registered");

            validators[pubkeyHash] =
                Validator({ pubkey: pubkey, operator: operator, status: ValidatorStatus.Active, optOutTimestamp: 0 });

            emit ValidatorRegistered(pubkeyHash, operator);
        }
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
        onlyRestakingMiddlewareContracts
    {
        _registerValidators(pubkeys, operator);
    }


    /// @notice Initiates the opt-out process for a validator
    /// @param pubKeyHash The hash of the validator's BLS public key
    /// @param signatureExpiry The expiry time of the signature
    /// @param signature The BLS signature proving control over the pubkey
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry, BLS12381.G2Point calldata signature) external {
        Validator storage validator = validators[pubKeyHash];

        require(validator.operator != address(0), "Validator not registered");
        require(validator.status == ValidatorStatus.Active, "Invalid status");
        require(block.timestamp <= signatureExpiry, "Signature expired");

        bytes memory message = abi.encodePacked(pubKeyHash, signatureExpiry);
        // require(BLS12381.verifySignature(validator.pubkey, message, signature), "Invalid signature");

        validator.status = ValidatorStatus.OptingOut;
        validator.optOutTimestamp = block.timestamp;

        emit ValidatorStatusChanged(pubKeyHash, ValidatorStatus.OptingOut);
    }

    /// @notice Confirms validator opt-out after cooldown period
    /// @param pubKeyHash The hash of the validator's BLS public key
    function confirmOptOut(bytes32 pubKeyHash) external {
        Validator storage validator = validators[pubKeyHash];
        require(validator.operator != address(0), "Validator not registered");
        require(validator.status == ValidatorStatus.OptingOut, "Validator not opting out");
        require(block.timestamp >= validator.optOutTimestamp + OPT_OUT_COOLDOWN, "Cooldown period not elapsed");

        validator.status = ValidatorStatus.OptedOut;
        validator.operator = address(0);
        validator.optOutTimestamp = 0;

        emit ValidatorOptedOut(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ValidatorStatus.OptedOut);
    }

    //////// VIEW ////////


    /// @notice Gets validator status by public key hash
    /// @param pubKeyHash Hash of the validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes32 pubKeyHash) external view returns (ValidatorStatus) {
        return validators[pubKeyHash].status;
    }

    /// @notice Gets validator status by public key
    /// @param pubKey The validator's public key
    /// @return The validator's status
    function getValidatorStatus(bytes calldata pubKey) external view returns (ValidatorStatus) {
        bytes32 pubKeyHash = _hashBLSPubKey(pubKey);
        return validators[pubKeyHash].status;
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

    //////// HELPER ////////

    /// @notice Hashes a BLS public key
    /// @param pubkey The BLS public key to hash
    /// @return The hash of the public key
    function _hashBLSPubKey(bytes calldata pubkey) internal pure returns (bytes32) {
        return keccak256(pubkey);
    }
}
