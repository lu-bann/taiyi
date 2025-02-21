// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiInteractiveChallenger } from "./interfaces/ITaiyiInteractiveChallenger.sol";
import { ITaiyiParameterManager } from "./interfaces/ITaiyiParameterManager.sol";
import { PreconfRequestAType } from "./types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "./types/PreconfRequestBTypes.sol";
import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { ECDSA } from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { ISP1Verifier } from "@sp1-contracts/ISP1Verifier.sol";

contract TaiyiInteractiveChallenger is ITaiyiInteractiveChallenger, Ownable {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifierGateway;

    /// @notice The verification key for the interactive fraud proof program.
    /// @dev When the verification key changes a new version of the contract must be deployed.
    bytes32 public interactiveFraudProofVKey;

    /// @notice TaiyiParameterManager contract.
    ITaiyiParameterManager public parameterManager;

    /// @notice Set of challenge IDs.
    EnumerableSet.Bytes32Set internal challengeIDs;

    /// @notice ID to challenge mapping.
    mapping(bytes32 => Challenge) internal challenges;

    /// @notice Count of open challenges.
    uint256 public openChallengeCount;

    constructor(
        address _initialOwner,
        address _verifierGateway,
        bytes32 _interactiveFraudProofVKey,
        address _parameterManagerAddress
    )
        Ownable(_initialOwner)
    {
        verifierGateway = _verifierGateway;
        interactiveFraudProofVKey = _interactiveFraudProofVKey;
        parameterManager = ITaiyiParameterManager(_parameterManagerAddress);
        openChallengeCount = 0;
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function setVerifierGateway(address _verifierGateway) external onlyOwner {
        verifierGateway = _verifierGateway;
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function setInteractiveFraudProofVKey(bytes32 _interactiveFraudProofVKey)
        external
        onlyOwner
    {
        interactiveFraudProofVKey = _interactiveFraudProofVKey;
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function getChallenges() external view returns (Challenge[] memory) {
        uint256 challengeCount = challengeIDs.length();
        Challenge[] memory challangesArray = new Challenge[](challengeCount);

        for (uint256 i = 0; i < challengeCount; i++) {
            challangesArray[i] = challenges[challengeIDs.at(i)];
        }

        return challangesArray;
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function getOpenChallenges() external view returns (Challenge[] memory) {
        Challenge[] memory openChallenges = new Challenge[](openChallengeCount);

        for (uint256 i = 0; i < openChallengeCount; i++) {
            openChallenges[i] = challenges[challengeIDs.at(i)];
        }

        return openChallenges;
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function getChallenge(bytes32 id) external view returns (Challenge memory) {
        if (!challengeIDs.contains(id)) {
            revert ChallengeDoesNotExist();
        }

        return challenges[id];
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function createChallengeAType(
        PreconfRequestAType calldata preconfRequestAType,
        bytes calldata signature
    )
        external
        payable
    {
        // Check challenge bond
        if (msg.value != parameterManager.challengeBond()) {
            revert ChallengeBondInvalid();
        }

        // We abi encode the preconfRequestAType to store it in the challenge struct
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);

        // We use the hash of the encoded preconfRequestAType as the challenge ID
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);

        // Recover the signer from the challenge ID and signature
        address signer = ECDSA.recover(challengeId, signature);

        // Verify that the signer matches the signer in the preconfRequestAType
        if (signer != preconfRequestAType.signer) {
            revert SignerDoesNotMatchPreconfRequest();
        }

        // Check if the challenge ID already exists
        if (challengeIDs.contains(challengeId)) {
            revert ChallengeAlreadyExists();
        }

        // TODO[Martin]: Decode txs and tipTx from preconfRequestAType

        // TODO[Martin]: Loop over txs and do necessary checks

        // TODO[Martin]: Target slot and sequence number checks ?

        // Add challenge
        challengeIDs.add(challengeId);
        challenges[challengeId] = Challenge(
            challengeId,
            block.timestamp,
            msg.sender,
            signer,
            address(0), // TODO[Martin]: Set correct address (extract from preconf request),
            ChallengeStatus.Open,
            0,
            encodedPreconfRequestAType,
            signature
        );
        openChallengeCount++;

        // Emit challenge opened event
        emit ChallengeOpened(challengeId, msg.sender, signer);
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function createChallengeBType(
        PreconfRequestBType calldata preconfRequestBType,
        bytes calldata signature
    )
        external
        payable
    {
        // Check challenge bond
        if (msg.value != parameterManager.challengeBond()) {
            revert ChallengeBondInvalid();
        }

        // TODO[Martin]: Implement
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function resolveExpiredChallenge(bytes32 id) external {
        if (!challengeIDs.contains(id)) {
            revert ChallengeDoesNotExist();
        }

        Challenge memory challenge = challenges[id];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (
            block.timestamp
                <= challenge.createdAt + parameterManager.challengeMaxDuration()
        ) {
            revert ChallengeNotExpired();
        }

        challenges[id].status = ChallengeStatus.Succeded;
        emit ChallengeSucceded(id);
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function prove(
        bytes32 id,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
    {
        address prover = msg.sender;

        if (!challengeIDs.contains(id)) {
            revert ChallengeDoesNotExist();
        }

        Challenge memory challenge = challenges[id];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (
            block.timestamp
                > challenge.createdAt + parameterManager.challengeMaxDuration()
        ) {
            revert ChallengeExpired();
        }

        // Verify the proof
        // ISP1Verifier(verifierGateway).verifyProof(
        //     interactiveFraudProofVKey, proofValues, proofBytes
        // );

        emit ChallengeFailed(id);
    }
}
