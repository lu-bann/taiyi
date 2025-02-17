// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequestAType } from "../types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "../types/PreconfRequestBTypes.sol";

interface ITaiyiInteractiveChallenger {
    struct Proof {
        uint256 inclusionBlockNumber;
    }
    // TODO[Martin]: Define other necessary proof fields

    enum ChallengeStatus {
        Open,
        Failed,
        Succeded
    }

    struct TypeAData {
        uint64 slot;
        bytes tipTx;
        bytes[] txs;
    }

    struct TypeBData {
        // TODO[Martin]: Define data struct PreconfRequestBType
        uint64 slot;
    }

    struct Challenge {
        bytes32 id;
        uint256 createdAt;
        address challenger;
        address commitmentSigner;
        address commitmentReceiver;
        ChallengeStatus status;
        uint8 preconfType; // 0 - TypeA | 1 - TypeB
        bytes commitmentData; // abi encoded commitment data (TypeAData or TypeBData)
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

    /// @notice Get a challenge by id.
    /// @param id The id of the challenge.
    /// @return challenge The challenge.
    function getChallenge(bytes32 id) external view returns (Challenge memory);

    /// @notice Create a new challenge.
    /// @param _preconfRequestAType The type A preconf request.
    function createChallengeAType(PreconfRequestAType calldata _preconfRequestAType)
        external
        payable;

    /// @notice Create a new challenge.
    /// @param _preconfRequestBType The type B preconf request.
    function createChallengeBType(PreconfRequestBType calldata _preconfRequestBType)
        external
        payable;

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
