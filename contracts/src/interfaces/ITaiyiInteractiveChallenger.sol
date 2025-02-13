// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface ITaiyiInteractiveChallenger {
    struct Proof {
        uint256 inclusionBlockNumber;
    }

    enum ChallengeStatus {
        Open,
        Failed,
        Succeded
    }

    struct Challenge {
        bytes32 id;
        uint256 createdAt;
        address challenger;
        address commitmentSigner;
        address commitmentReceiver;
        ChallengeStatus status;
    }

    error BlockIsTooOld();
    error InvalidBlockNumber();

    error ChallengeAlreadyDefended();
    error ChallengeAlreadyExists();
    error ChallengeDoesNotExist();
    error ChallengeExpired();
    error ChallengeNotExpired();

    event ChallengeOpened(
        bytes32 indexed id, address indexed challenger, address indexed commitmentSigner
    );
    event ChallengeFailed(bytes32 indexed id);
    event ChallengeSucceded(bytes32 indexed id);

    /// @notice Get all challenges.
    /// @return challenges An array of challenges.
    function getChallenges() external view returns (Challenge[] memory);

    /// @notice Get all open challenges.
    /// @return challenges An array of open challenges.
    function getOpenChallenges() external view returns (Challenge[] memory);
    function getChallenge(bytes32 id) external view returns (Challenge memory);

    // TODO[Martin]: Define input for creating a challenge
    /// @notice Create a new challenge.
    function createChallenge() external payable;

    /// @notice Resolve an expired challenge.
    /// @dev This function can be called by anyone to resolve an expired challenge.
    /// @param id The id of the expired challenge.
    function resolveExpiredChallenge(bytes32 id) external;

    /// @notice Set the address of the SP1 gateway contract.
    /// @param _verifierGateway The address of the SP1 gateway contract.
    function setVerifierGateway(address _verifierGateway) external;

    /// @notice Set the verification key for the interactive fraud proof program.
    /// @param _interactiveFraudProofVKey The verification key.
    function setInteractiveFraudProofVKey(bytes32 _interactiveFraudProofVKey) external;

    /// @notice The entrypoint for defending against an open challenge using a SP1 proof of execution.
    /// @param id The id of the challenge to defend against.
    /// @param proofValues The encoded public values.
    /// @param proofBytes The encoded proof.
    function prove(
        bytes32 id,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external;
}
