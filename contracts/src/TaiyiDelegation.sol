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

    // Mapping to track registered Preconfers
    mapping(address => bool) public registeredPreconfers;

    // Mapping from validator pubKeyHash to Preconfer address
    mapping(bytes32 => PreconferElection) public validatorToPreconfer;

    // Mapping to prevent frequent delegation changes (DDOS mitigation)
    mapping(bytes32 => uint256) public lastDelegationChangeTimestamp;

    // Cooldown period for delegation changes (assuming 12 second block time)
    uint256 public constant DELEGATION_CHANGE_COOLDOWN = 64 * 12 seconds;

    constructor(address _proposerRegistry) {
        proposerRegistry = IProposerRegistry(_proposerRegistry);
    }

    /**
     * @notice Registers a Preconfer to allow them to receive delegations
     * @param Preconfer The address of the Preconfer
     */
    function registerPreconfer(address Preconfer) external override {
        require(!registeredPreconfers[Preconfer], "Already registered");
        registeredPreconfers[Preconfer] = true;
        emit PreconferRegistered(Preconfer);
    }

    /**
     * @notice Deregisters a Preconfer
     * @param Preconfer The address of the Preconfer
     */
    function deregisterPreconfer(address Preconfer) external override {
        require(registeredPreconfers[Preconfer], "Not registered");
        registeredPreconfers[Preconfer] = false;
        emit PreconferDeregistered(Preconfer);
    }

    /**
     * @notice Checks if a Preconfer is registered
     * @param Preconfer The address of the Preconfer
     * @return True if registered, false otherwise
     */
    function isRegisteredPreconfer(address Preconfer) public view override returns (bool) {
        return registeredPreconfers[Preconfer];
    }

    /**
     * @notice Allows a validator to delegate preconfirmation duties to a Preconfer
     * @param preconferElection The struct containing delegation details
     */
    function delegatePreconfDuty(PreconferElection calldata preconferElection) external {
        bytes32 validatorPubKeyHash = hashBLSPubKey(preconferElection.validatorPubkey);

        IProposerRegistry.Validator memory validator = proposerRegistry.getValidator(validatorPubKeyHash);
        require(validator.registrar == msg.sender, "Caller is not validator registrar");
        require(validator.status == IProposerRegistry.ProposerStatus.OptIn, "Validator not opted in");
        require(isRegisteredPreconfer(preconferElection.preconferAddress), "Invalid Preconfer");
        require(validatorToPreconfer[validatorPubKeyHash].preconferAddress == address(0), "Validator already delegated");

        // Check cooldown period
        require(
            block.timestamp >= lastDelegationChangeTimestamp[validatorPubKeyHash] + DELEGATION_CHANGE_COOLDOWN,
            "Delegation change cooldown active"
        );

        // Verify that the Preconfer is registered
        require(registeredPreconfers[preconferElection.preconferAddress], "Preconfer not registered");

        // Construct the message to be signed
        // bytes memory message = abi.encodePacked(preconferElection.preconferAddress);

        // Verify BLS signature
        // require(verifySignature(message, signature, preconferElection.validatorPubkey), "Invalid BLS signature");

        // Update delegation mapping
        validatorToPreconfer[validatorPubKeyHash].preconferAddress = preconferElection.preconferAddress;
        lastDelegationChangeTimestamp[validatorPubKeyHash] = block.timestamp;
        validator.delegatee = preconferElection.preconferAddress;

        emit ValidatorDelegated(validatorPubKeyHash, preconferElection.preconferAddress);
    }

    function batchDelegatePreconfDuty(PreconferElection[] calldata preconferElections) external {
        for (uint256 i = 0; i < preconferElections.length; i++) {
            this.delegatePreconfDuty(preconferElections[i]);
        }
    }

    function revokeDelegation(bytes32 validatorPubKeyHash)
        // uint256 signatureExpiry
        // BLS12381.G2Point calldata signature
        external
    {
        IProposerRegistry.Validator memory validator = proposerRegistry.getValidator(validatorPubKeyHash);
        require(validator.registrar == msg.sender, "Caller is not validator registrar");
        require(validatorToPreconfer[validatorPubKeyHash].preconferAddress != address(0), "No delegation to revoke");
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

        address Preconfer = validatorToPreconfer[validatorPubKeyHash].preconferAddress;
        validatorToPreconfer[validatorPubKeyHash].preconferAddress = address(0);
        lastDelegationChangeTimestamp[validatorPubKeyHash] = block.timestamp;
        validator.delegatee = address(0);

        emit DelegationRevoked(validatorPubKeyHash, Preconfer);
    }

    /**
     * @notice Retrieves the delegated Preconfer for a validator
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @return The address of the delegated Preconfer
     */
    function getDelegatedPreconfer(bytes32 validatorPubKeyHash) external view override returns (address) {
        return validatorToPreconfer[validatorPubKeyHash].preconferAddress;
    }

    /**
     * @notice Internal helper to hash a BLS public key
     * @param pubkey The BLS public key
     * @return Hash of the compressed BLS public key
     */
    function hashBLSPubKey(bytes memory pubkey) public pure returns (bytes32) {
        // uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(pubkey);
    }
}
