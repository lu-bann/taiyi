// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequestAType } from "../types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "../types/PreconfRequestBTypes.sol";

interface ITaiyiNonInteractiveChallenger {
    struct Proof {
        // TODO[Martin]: Define other necessary proof fields
        uint256 inclusionBlockNumber;
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

    // TODO[Martin]: Do we want to store only successful challenges? or also failed ones?
    struct Challenge {
        bytes32 id;
        uint256 createdAt;
        address challenger;
        address commitmentSigner;
        address commitmentReceiver;
        uint8 preconfType; // 0 - TypeA | 1 - TypeB
        bytes commitmentData; // abi encoded commitment data (TypeAData or TypeBData)
    }

    error BlockIsTooOld();
    error InvalidBlockNumber();
    error ChallengeAlreadySucceeded();

    event ChallengeSucceded(
        bytes32 indexed id, address indexed challenger, address indexed commitmentSigner
    );

    /// @notice Get all challenges.
    /// @return challenges An array of challenges.
    function getChallenges() external view returns (Challenge[] memory);

    /// @notice Get a challenge by id.
    /// @param id The id of the challenge.
    /// @return challenge The challenge.
    function getChallenge(bytes32 id) external view returns (Challenge memory);

    /// @notice Create a new challenge.
    /// @param _preconfRequestAType The type A preconf request.
    function createChallengeAType(
        PreconfRequestAType calldata _preconfRequestAType,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
        payable;

    /// @notice Create a new challenge.
    /// @param _preconfRequestBType The type B preconf request.
    function createChallengeBType(
        PreconfRequestBType calldata _preconfRequestBType,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
        payable;

    /// @notice Set the address of the SP1 gateway contract.
    /// @param _verifierGateway The address of the SP1 gateway contract.
    function setVerifierGateway(address _verifierGateway) external;

    /// @notice Set the verification key for the interactive fraud proof program.
    /// @param _interactiveFraudProofVKey The verification key.
    function setNonInteractiveFraudProofVKey(bytes32 _interactiveFraudProofVKey)
        external;
}
