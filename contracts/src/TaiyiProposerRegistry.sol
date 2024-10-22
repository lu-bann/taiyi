// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {BLS12381} from "./libs/BLS12381.sol"; 
import {BLSSignatureChecker} from "./libs/BLSSignatureChecker.sol"; 

contract TaiyiProposerRegistry is BLSSignatureChecker {
    using BLS12381 for BLS12381.G1Point;

    // Enum to represent the status of a proposer
    enum ProposerStatus {
        OptedOut,
        OptIn,
        OptingOut
    }

    // Validator struct containing all necessary information
    struct Validator {
        BLS12381.G1Point pubkey;
        address controller; // Ethereum address controlling the validator
        ProposerStatus status;
        uint256 stake;
        uint256 optOutTimestamp;
    }

    // Mapping from BLS public key hash to Validator structs
    mapping(bytes32 => Validator) public validators;

    // Constants for staking and cooldown periods
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;
    uint256 public constant STAKE_AMOUNT = 0.01 ether; // Placeholder value; adjust as needed

    // Events for logging validator actions
    event ValidatorOptedIn(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorOptedOut(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorStatusChanged(bytes32 indexed pubKeyHash, ProposerStatus status);

    constructor() {}

    /**
     * @notice Registers a validator with the given BLS public key and stake
     * @param pubkey The BLS public key of the validator
     * @param signatureExpiry The expiry time of the signature
     * @param signature The BLS signature proving control over the pubkey
     */
    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        uint256 signatureExpiry,
        BLS12381.G2Point calldata signature
    ) external payable {
        require(msg.value == STAKE_AMOUNT, "Incorrect stake amount");
        bytes32 pubKeyHash = _hashBLSPubKey(pubkey);
        require(validators[pubKeyHash].controller == address(0), "Validator already registered");

        // Construct message to sign
        bytes memory message = abi.encodePacked(block.chainid, signatureExpiry, msg.sender);
        // Verify BLS signature
        require(block.timestamp <= signatureExpiry, "Signature expired");
        require(BLSSignatureChecker.verifySignature(message, signature, pubkey), "Invalid BLS signature");

        validators[pubKeyHash] = Validator({
            pubkey: pubkey,
            controller: msg.sender,
            status: ProposerStatus.OptIn,
            stake: msg.value,
            optOutTimestamp: 0
        });

        emit ValidatorOptedIn(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ProposerStatus.OptIn);
    }

    /**
     * @notice Initiates the opt-out process for a validator
     * @param pubKeyHash The hash of the validator's BLS public key
     */
    function initOptOut(bytes32 pubKeyHash) external {
        Validator storage validator = validators[pubKeyHash];
        require(validator.controller == msg.sender, "Not the validator controller");
        require(validator.status == ProposerStatus.OptIn, "Invalid status");
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
        require(validator.controller == msg.sender, "Not the validator controller");
        require(validator.status == ProposerStatus.OptingOut, "Validator not opting out");
        require(
            block.timestamp >= validator.optOutTimestamp + OPT_OUT_COOLDOWN,
            "Cooldown period not elapsed"
        );

        uint256 stakeAmount = validator.stake;
        validator.status = ProposerStatus.OptedOut;
        validator.controller = address(0);
        validator.stake = 0;
        validator.optOutTimestamp = 0;

        (bool sent, ) = msg.sender.call{value: stakeAmount}("");
        require(sent, "Failed to return stake");

        emit ValidatorOptedOut(pubKeyHash, msg.sender);
        emit ValidatorStatusChanged(pubKeyHash, ProposerStatus.OptedOut);
    }

    /**
     * @notice Returns the status of a validator
     * @param pubKeyHash The hash of the validator's BLS public key
     * @return The proposer's status
     */
    function getValidatorStatus(bytes32 pubKeyHash) external view returns (ProposerStatus) {
        return validators[pubKeyHash].status;
    }

    /**
     * @notice Internal helper to hash a BLS public key
     * @param pubkey The BLS public key
     * @return Hash of the compressed BLS public key
     */
    function _hashBLSPubKey(BLS12381.G1Point calldata pubkey) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }

    // Include verifySignature function from BLSSignatureChecker
    // Ensure that BLSSignatureChecker provides this functionality
}