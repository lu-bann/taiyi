// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequestAType } from "../types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "../types/PreconfRequestBTypes.sol";

interface ITaiyiInteractiveChallenger {
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
        ChallengeStatus status;
        uint8 preconfType; // 0 - TypeA | 1 - TypeB
        bytes commitmentData; // abi encoded commitment data (PreconfRequestAType | PreconfRequestBType)
        bytes signature; // signed digest of the commitment data
    }

    error TargetSlotNotInChallengeCreationWindow();
    error SignerDoesNotMatchPreconfRequest();
    error ChallengeBondInvalid();
    error ChallengeAlreadyResolved();
    error ChallengeAlreadyExists();
    error ChallengeDoesNotExist();
    error ChallengeExpired();
    error ChallengeNotExpired();
    // Proof verification errors
    error TargetSlotDoesNotMatch();
    error GenesisTimestampDoesNotMatch();
    error TaiyiCoreAddressDoesNotMatch();
    error ChallengeIdDoesNotMatch();
    error CommitmentSignerDoesNotMatch();

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

    /// @notice Get a challenge by id.
    /// @param id The id of the challenge.
    /// @return challenge The challenge.
    function getChallenge(bytes32 id) external view returns (Challenge memory);

    /// @notice Create a new challenge.
    /// @param preconfRequestAType The type A preconf request.
    /// @param signature The signature over the commitment data.
    function createChallengeAType(
        PreconfRequestAType calldata preconfRequestAType,
        bytes calldata signature
    )
        external
        payable;

    /// @notice Create a new challenge.
    /// @param preconfRequestBType The type B preconf request.
    /// @param signature The signature over the commitment data.
    function createChallengeBType(
        PreconfRequestBType calldata preconfRequestBType,
        bytes calldata signature
    )
        external
        payable;

    /// @notice Resolve an expired challenge.
    /// @dev This function can be called by anyone to resolve an expired challenge.
    /// @param id The id of the expired challenge.
    function resolveExpiredChallenge(bytes32 id) external;

    /// @notice Set the address of the SP1 underwriter contract.
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
