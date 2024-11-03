// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BLS12381 } from "../libs/BLS12381.sol";

interface IProposerRegistry {
    // Enum to represent the status of a proposer
    enum ProposerStatus {
        OptedOut,
        OptIn,
        OptingOut
    }

    // Validator struct containing all necessary information
    struct Validator {
        bytes pubkey;
        ProposerStatus status;
        uint256 optOutTimestamp;
        address registrar;
        address delegatee;
    }

    // Events
    event ValidatorOptedIn(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorOptedOut(bytes32 indexed pubKeyHash, address indexed controller);
    event ValidatorStatusChanged(bytes32 indexed pubKeyHash, ProposerStatus status);

    /**
     * @notice Registers a validator with the given BLS public key
     * @param pubkey The BLS public key of the validator
     */
    function registerValidator(
        bytes calldata pubkey,
        // uint256 signatureExpiry,
        // BLS12381.G2Point calldata signature,
        address delegatee
    )
        external
        payable;

    /**
     * @notice Initiates the opt-out process for a validator
     * @param pubKeyHash The hash of the validator's BLS public key
     * @param signatureExpiry The expiry time of the signature
     * @param signature The BLS signature proving control over the pubkey
     */
    function initOptOut(bytes32 pubKeyHash, uint256 signatureExpiry, BLS12381.G2Point calldata signature) external;

    /**
     * @notice Confirms the opt-out process after the cooldown period
     * @param pubKeyHash The hash of the validator's BLS public key
     */
    function confirmOptOut(bytes32 pubKeyHash) external;

    /**
     * @notice Returns the status of a validator
     * @param pubKeyHash The hash of the validator's BLS public key
     * @return The proposer's status
     */
    function getValidatorStatus(bytes32 pubKeyHash) external view returns (ProposerStatus);

    /// @notice The cooldown period required before completing opt-out
    function OPT_OUT_COOLDOWN() external view returns (uint256);

    /**
     * @notice Returns the validator information for a given public key hash
     * @param pubKeyHash The hash of the validator's BLS public key
     * @return The Validator struct containing all validator information
     */
    function getValidator(bytes32 pubKeyHash) external view returns (Validator memory);
}
