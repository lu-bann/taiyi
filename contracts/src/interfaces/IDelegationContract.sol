// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BLS12381 } from "../libs/BLS12381.sol";

interface IDelegationContract {
    /**
     * @notice Event emitted when a preconfirmer is registered
     * @param preconfirmer The address of the registered preconfirmer
     */
    event PreconfirmerRegistered(address indexed preconfirmer);

    /**
     * @notice Event emitted when a validator delegates to a preconfirmer
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @param preconfirmer The address of the preconfirmer
     */
    event ValidatorDelegated(bytes32 indexed validatorPubKeyHash, address indexed preconfirmer);

    /**
     * @notice Event emitted when a preconfirmer is deregistered
     * @param preconfirmer The address of the deregistered preconfirmer
     */
    event PreconfirmerDeregistered(address indexed preconfirmer);

    /**
     * @notice Event emitted when a delegation is revoked
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @param preconfirmer The address of the preconfirmer
     */
    event DelegationRevoked(bytes32 indexed validatorPubKeyHash, address indexed preconfirmer);

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
     * @notice Registers a preconfirmer to allow them to receive delegations
     * @param preconfirmer The address of the preconfirmer
     */
    function registerPreconfirmer(address preconfirmer) external;

    /**
     * @notice Deregisters a preconfirmer
     * @param preconfirmer The address of the preconfirmer
     */
    function deregisterPreconfirmer(address preconfirmer) external;

    /**
     * @notice Checks if a preconfirmer is registered
     * @param preconfirmer The address of the preconfirmer
     * @return True if registered, false otherwise
     */
    function isRegisteredPreconfirmer(address preconfirmer) external view returns (bool);

    /**
     * @notice Allows a validator to delegate preconfirmation duties to a preconfirmer
     * @param preconferElection The struct containing delegation details
     */
    function delegatePreconfDuty(PreconferElection calldata preconferElection)
        // BLS12381.G2Point memory signature
        external;

    /**
     * @notice Retrieves the delegated preconfirmer for a validator
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     * @return The address of the delegated preconfirmer
     */
    function getDelegatedPreconfirmer(bytes32 validatorPubKeyHash) external view returns (address);

    /**
     * @notice Allows a validator to revoke their delegation
     * @param validatorPubKeyHash The hash of the validator's BLS public key
     */
    function revokeDelegation(bytes32 validatorPubKeyHash)
        // uint256 signatureExpiry,
        // BLS12381.G2Point calldata signature
        external;
}
