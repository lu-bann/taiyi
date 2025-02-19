// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequestAType } from "../types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "../types/PreconfRequestBTypes.sol";

interface ITaiyiNonInteractiveChallenger {
    struct Proof {
        // TODO[Martin]: Define other necessary proof fields
        uint256 inclusionBlockNumber;
    }

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

    /// @notice Proves a type A challenge.
    /// @param preconfRequestAType The type A preconf request.
    /// @param signature The signature over the commitment data.
    /// @param proofValues The encoded public values.
    /// @param proofBytes The encoded proof.
    function proveAType(
        PreconfRequestAType calldata preconfRequestAType,
        bytes calldata signature,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
        payable;

    /// @notice Proves a type B challenge.
    /// @param preconfRequestBType The type B preconf request.
    /// @param signature The signature over the commitment data.
    /// @param proofValues The encoded public values.
    /// @param proofBytes The encoded proof.
    function proveBType(
        PreconfRequestBType calldata preconfRequestBType,
        bytes calldata signature,
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
