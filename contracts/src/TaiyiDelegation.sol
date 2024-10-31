// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./interfaces/IDelegationContract.sol";
import "./interfaces/IProposerRegistry.sol";
import { EnumerableMap } from "open-zeppelin/utils/structs/EnumerableMap.sol";
import { BLS12381 } from "./libs/BLS12381.sol";
import { BLSSignatureChecker } from "./libs/BLSSignatureChecker.sol";

contract TaiyiDelegation is IDelegationContract, BLSSignatureChecker {
    using BLS12381 for BLS12381.G1Point;
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    // Reference to the TaiyiProposerRegistry
    IProposerRegistry public proposerRegistry;

    // Mapping to track registered preconfirmers
    mapping(address => bool) public registeredPreconfirmers;

    // Mapping from validator pubKeyHash to preconfirmer address
    mapping(bytes32 => address) public validatorToPreconfirmer;

    // Mapping to prevent frequent delegation changes (DDOS mitigation)
    mapping(bytes32 => uint256) public lastDelegationChangeTimestamp;

    // Cooldown period for delegation changes (assuming 12 second block time)
    uint256 public constant DELEGATION_CHANGE_COOLDOWN = 64 * 12 seconds;

    constructor(address _proposerRegistry) {
        proposerRegistry = IProposerRegistry(_proposerRegistry);
    }

    /**
     * @notice Registers a preconfirmer to allow them to receive delegations
     * @param preconfirmer The address of the preconfirmer
     */
    function registerPreconfirmer(address preconfirmer) external override {
        require(!registeredPreconfirmers[preconfirmer], "Already registered");
        registeredPreconfirmers[preconfirmer] = true;
        emit PreconfirmerRegistered(preconfirmer);
    }

    /**
     * @notice Deregisters a preconfirmer
     * @param preconfirmer The address of the preconfirmer
     */
    function deregisterPreconfirmer(address preconfirmer) external override {
        require(registeredPreconfirmers[preconfirmer], "Not registered");
        registeredPreconfirmers[preconfirmer] = false;
        emit PreconfirmerDeregistered(preconfirmer);
    }

    /**
     * @notice Checks if a preconfirmer is registered
     * @param preconfirmer The address of the preconfirmer
     * @return True if registered, false otherwise
     */
    function isRegisteredPreconfirmer(address preconfirmer) public view override returns (bool) {
        return registeredPreconfirmers[preconfirmer];
    }

    /**
     * @notice Allows a validator to delegate preconfirmation duties to a preconfirmer
     * @param preconferElection The struct containing delegation details
     */
    function delegatePreconfDuty(PreconferElection calldata preconferElection)
        // BLS12381.G2Point calldata signature
        external
    {
        bytes32 validatorPubKeyHash = _hashBLSPubKey(preconferElection.validatorPubkey);

        IProposerRegistry.Validator memory validator = proposerRegistry.getValidator(validatorPubKeyHash);
        require(validator.registrar == msg.sender, "Caller is not validator registrar");
        require(validator.status == IProposerRegistry.ProposerStatus.OptIn, "Validator not opted in");
        require(isRegisteredPreconfirmer(preconferElection.preconferAddress), "Invalid preconfirmer");
        require(validatorToPreconfirmer[validatorPubKeyHash] == address(0), "Validator already delegated");

        // Check cooldown period
        require(
            block.timestamp >= lastDelegationChangeTimestamp[validatorPubKeyHash] + DELEGATION_CHANGE_COOLDOWN,
            "Delegation change cooldown active"
        );

        // Verify that the preconfirmer is registered
        require(registeredPreconfirmers[preconferElection.preconferAddress], "Preconfirmer not registered");

        // Construct the message to be signed
        // bytes memory message = abi.encodePacked(preconferElection.preconferAddress);

        // Verify BLS signature
        // require(verifySignature(message, signature, preconferElection.validatorPubkey), "Invalid BLS signature");

        // Update delegation mapping
        validatorToPreconfirmer[validatorPubKeyHash] = preconferElection.preconferAddress;
        lastDelegationChangeTimestamp[validatorPubKeyHash] = block.timestamp;
        validator.delegatee = preconferElection.preconferAddress;

        emit ValidatorDelegated(validatorPubKeyHash, preconferElection.preconferAddress);
    }

    function revokeDelegation(bytes32 validatorPubKeyHash)
        // uint256 signatureExpiry
        // BLS12381.G2Point calldata signature
        external
    {
        IProposerRegistry.Validator memory validator = proposerRegistry.getValidator(validatorPubKeyHash);
        require(validator.registrar == msg.sender, "Caller is not validator registrar");
        require(validatorToPreconfirmer[validatorPubKeyHash] != address(0), "No delegation to revoke");
        // require(block.timestamp <= signatureExpiry, "Signature expired");

        // Construct message to sign (similar to how it's done in ProposerRegistry's initOptOut)
        // bytes memory message = abi.encodePacked(address(0), signatureExpiry);

        // Verify BLS signature
        // require(verifySignature(message, signature, validator.pubkey), "Invalid BLS signature");

        // Check cooldown period
        require(
            block.timestamp >= lastDelegationChangeTimestamp[validatorPubKeyHash] + DELEGATION_CHANGE_COOLDOWN,
            "Delegation change cooldown active"
        );

        address preconfirmer = validatorToPreconfirmer[validatorPubKeyHash];
        validatorToPreconfirmer[validatorPubKeyHash] = address(0);
        lastDelegationChangeTimestamp[validatorPubKeyHash] = block.timestamp;
        validator.delegatee = address(0);

        emit DelegationRevoked(validatorPubKeyHash, preconfirmer);
    }

    /**
     * @notice Retrieves the delegated preconfirmer for a validator
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @return The address of the delegated preconfirmer
     */
    function getDelegatedPreconfirmer(bytes32 validatorPubKeyHash) external view override returns (address) {
        return validatorToPreconfirmer[validatorPubKeyHash];
    }

    /**
     * @notice Internal helper to hash a BLS public key
     * @param pubkey The BLS public key
     * @return Hash of the compressed BLS public key
     */
    function _hashBLSPubKey(BLS12381.G1Point memory pubkey) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }

    /**
     * @notice Public wrapper for _hashBLSPubKey function
     * @param pubkey The BLS public key to hash
     * @return bytes32 Hash of the compressed BLS public key
     */
    function hashBLSPubKey(BLS12381.G1Point memory pubkey) public pure returns (bytes32) {
        return _hashBLSPubKey(pubkey);
    }
}
