// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BLS12381 } from "../libs/BLS12381.sol";

interface IDelegationContract {
    /**
     * @notice Event emitted when a Preconfer is registered
     * @param Preconfer The address of the registered Preconfer
     */
    event PreconferRegistered(address indexed Preconfer);

    /**
     * @notice Event emitted when a validator delegates to a Preconfer
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @param Preconfer The address of the Preconfer
     */
    event ValidatorDelegated(
        bytes32 indexed validatorPubKeyHash, address indexed Preconfer
    );

    /**
     * @notice Event emitted when a Preconfer is deregistered
     * @param Preconfer The address of the deregistered Preconfer
     */
    event PreconferDeregistered(address indexed Preconfer);

    /**
     * @notice Event emitted when a delegation is revoked
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @param Preconfer The address of the Preconfer
     */
    event DelegationRevoked(
        bytes32 indexed validatorPubKeyHash, address indexed Preconfer
    );

    /**
     * @notice Struct representing the preconfer election details
     */
    struct PreconferElection {
        bytes validatorPubkey;
        bytes preconferPubkey;
        uint256 chainId;
        address preconferAddress;
    }

    /**
     * @notice Registers a Preconfer to allow them to receive delegations
     * @param Preconfer The address of the Preconfer
     */
    function registerPreconfer(address Preconfer) external;

    /**
     * @notice Deregisters a Preconfer
     * @param Preconfer The address of the Preconfer
     */
    function deregisterPreconfer(address Preconfer) external;

    /**
     * @notice Checks if a Preconfer is registered
     * @param Preconfer The address of the Preconfer
     * @return True if registered, false otherwise
     */
    function isRegisteredPreconfer(address Preconfer) external view returns (bool);

    /**
     * @notice Allows a validator to delegate preconfirmation duties to a
     * Preconfer
     * @param preconferElection The struct containing delegation details
     */
    function delegatePreconfDuty(PreconferElection calldata preconferElection)
        // BLS12381.G2Point memory signature
        external;

    /**
     * @notice Retrieves the delegated Preconfer for a validator
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @return The address of the delegated Preconfer
     */
    function getDelegatedPreconfer(bytes32 validatorPubKeyHash)
        external
        view
        returns (address);

    /**
     * @notice Allows a validator to revoke their delegation
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     */
    function revokeDelegation(bytes32 validatorPubKeyHash)
        // uint256 signatureExpiry,
        // BLS12381.G2Point calldata signature
        external;
}
