// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";
import { IProposerRegistry } from "./interfaces/IProposerRegistry.sol";

contract TaiyiProposerRegistry is IProposerRegistry, BLSSignatureChecker {
    using BLS12381 for BLS12381.G1Point;

    // Mapping from BLS public key hash to Validator structs
    mapping(bytes32 => Validator) public validators;

    // Constants for staking and cooldown periods
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;

    constructor() { }

    //////// REGISTRATION ////////

    function registerValidator(bytes calldata pubkey, address delegatee) external payable {
        _registerValidator(pubkey, delegatee, msg.sender);
    }

    /**
     * @notice Registers a validator with the given BLS public key and stake
     * @param pubkey The BLS public key of the validator
     */
    function _registerValidator(
        bytes calldata pubkey,
        // uint256 signatureExpiry,
        // BLS12381.G2Point calldata signature,
        address delegatee,
        address sender
    )
        private
    {
        // Construct message to sign
        // bytes memory message = abi.encodePacked(ProposerStatus.OptIn, signatureExpiry, msg.sender);

        // Verify BLS signature
        // require(block.timestamp <= signatureExpiry, "Signature expired");
        // require(BLSSignatureChecker.verifySignature(message, signature, pubkey), "Invalid BLS signature");

        bytes32 pubKeyHash = _hashBLSPubKey(pubkey);
        require(validators[pubKeyHash].registrar == address(0), "Validator already registered");

        validators[pubKeyHash] = Validator({
            pubkey: pubkey,
            registrar: msg.sender,
            status: ProposerStatus.OptIn,
            optOutTimestamp: 0,
            delegatee: delegatee
        });

        emit ValidatorOptedIn(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ProposerStatus.OptIn);
    }

    function batchRegisterValidators(bytes[] calldata pubkeys, address[] calldata delegatees) external payable {
        for (uint256 i = 0; i < pubkeys.length; i++) {
            _registerValidator(pubkeys[i], delegatees[i], msg.sender);
        }
    }

    /**
     * @notice Initiates the opt-out process for a validator
     * @param pubKeyHash The hash of the validator's BLS public key
     * @param signatureExpiry The expiry time of the signature
     * @param signature The BLS signature proving control over the pubkey
     */
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry, BLS12381.G2Point calldata signature) external {
        Validator storage validator = validators[pubKeyHash];

        // Ensure the validator exists and is currently opted in
        require(validator.registrar != address(0), "Validator not registered");
        require(validator.status == ProposerStatus.OptIn, "Invalid status");

        // Construct message to sign
        bytes memory message = abi.encodePacked(ProposerStatus.OptingOut, signatureExpiry, msg.sender);

        // Verify BLS signature
        // require(block.timestamp <= signatureExpiry, "Signature expired");
        // require(BLSSignatureChecker.verifySignature(message, signature, validator.pubkey), "Invalid BLS signature");

        // Update validator status
        validator.status = ProposerStatus.OptingOut;
        validator.optOutTimestamp = block.timestamp;

        emit ValidatorStatusChanged(pubKeyHash, ProposerStatus.OptingOut);
    }

    /**
     * @notice Confirms the opt-out process after the cooldown period
     * @param pubKeyHash The hash of the validator's BLS public key
     */
    function confirmOptOut(bytes32 pubKeyHash) external {
        Validator storage validator = validators[pubKeyHash];
        require(validator.registrar == msg.sender, "Not the validator registrar");
        require(validator.status == ProposerStatus.OptingOut, "Validator not opting out");
        require(block.timestamp >= validator.optOutTimestamp + OPT_OUT_COOLDOWN, "Cooldown period not elapsed");

        validator.status = ProposerStatus.OptedOut;
        validator.registrar = address(0);
        validator.optOutTimestamp = 0;

        emit ValidatorOptedOut(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ProposerStatus.OptedOut);
    }

    //////// VIEW ////////

    /**
     * @notice Returns the status of a validator
     * @param pubKeyHash The hash of the validator's BLS public key
     * @return The proposer's status
     */
    function getValidatorStatus(bytes32 pubKeyHash) external view returns (ProposerStatus) {
        return validators[pubKeyHash].status;
    }

    /**
     * @notice Returns the validator information for a given public key hash
     * @param pubKeyHash The hash of the validator's BLS public key
     * @return The Validator struct containing all validator information
     */
    function getValidator(bytes32 pubKeyHash) public view returns (Validator memory) {
        return validators[pubKeyHash];
    }

    /**
     * @notice Returns the delegatee address for a given validator
     * @param pubKeyHash The hash of the validator's BLS public key
     * @return The address of the delegatee, or address(0) if none
     */
    function getDelegatee(bytes32 pubKeyHash) external view returns (address) {
        return validators[pubKeyHash].delegatee;
    }

    //////// HELPER ////////

    /**
     * @notice Internal helper to hash a BLS public key
     * @param pubkey The BLS public key
     * @return Hash of the compressed BLS public key
     */
    function _hashBLSPubKey(bytes calldata pubkey) internal pure returns (bytes32) {
        // uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(pubkey);
    }
}
