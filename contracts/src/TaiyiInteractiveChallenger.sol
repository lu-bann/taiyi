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

struct PublicValuesStruct {
    uint64 proofBlockNumber;
    bytes32 proofBlockHash;
    address gatewayAddress;
    bytes signature;
}

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
        uint256 totalChallengeCount = challengeIDs.length();
        uint256 counter = 0;

        Challenge[] memory openChallenges = new Challenge[](openChallengeCount);

        for (uint256 i = 0; i < totalChallengeCount; i++) {
            bytes32 challengeId = challengeIDs.at(i);

            if (challenges[challengeId].status == ChallengeStatus.Open) {
                openChallenges[counter] = challenges[challengeId];
                counter++;
            }
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

    // TODO: Update function after we finalize the PreconfRequestAType format/interface
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

        // Check if the challenge ID already exists
        if (challengeIDs.contains(challengeId)) {
            revert ChallengeAlreadyExists();
        }

        // Add challenge
        challengeIDs.add(challengeId);
        challenges[challengeId] = Challenge(
            challengeId,
            block.timestamp,
            msg.sender,
            signer,
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

        if (
            preconfRequestBType.blockspaceAllocation.targetSlot
                < _getSlotFromTimestamp(block.timestamp)
                    - parameterManager.challengeCreationWindow()
                || preconfRequestBType.blockspaceAllocation.targetSlot
                    > _getSlotFromTimestamp(block.timestamp)
        ) {
            revert TargetSlotNotInChallengeCreationWindow();
        }

        // TODO: Do we want to wait for the target slot to be finalized (reorgs) ?

        bytes memory encodedPreconfRequestBType = abi.encode(preconfRequestBType);

        // TODO: This probably needs the hash of the rawTx
        // TODO: Probably also need to call MessageHashUtils-toEthSignedMessageHash
        bytes32 dataHash = keccak256(
            abi.encode(
                preconfRequestBType.blockspaceAllocation, preconfRequestBType.rawTx
            )
        );

        // Recover the signer of the preconf request (revert if the signature is invalid)
        address signer = ECDSA.recover(dataHash, signature);

        // TODO: Is the Bond enough to prevent someone to spam create challenges
        // or should we verify the signer is a valid/staked validator (for slashing)

        // Compute challenge ID from the preconf request signature
        bytes32 challengeId = keccak256(signature);

        // Check if the challenge ID already exists
        if (challengeIDs.contains(challengeId)) {
            revert ChallengeAlreadyExists();
        }

        // Add challenge
        Challenge memory challenge = Challenge(
            challengeId,
            block.timestamp,
            msg.sender,
            signer,
            ChallengeStatus.Open,
            1,
            encodedPreconfRequestBType,
            signature
        );

        challengeIDs.add(challengeId);
        challenges[challengeId] = challenge;
        openChallengeCount++;

        // Emit challenge opened event
        emit ChallengeOpened(challengeId, msg.sender, signer);
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
        openChallengeCount--;
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
        ISP1Verifier(verifierGateway).verifyProof(
            interactiveFraudProofVKey, proofValues, proofBytes
        );

        // Decode proof values
        PublicValuesStruct memory publicValues =
            abi.decode(proofValues, (PublicValuesStruct));

        // Decode preconf request from challenge data
        PreconfRequestBType memory preconfRequestBType =
            abi.decode(challenge.commitmentData, (PreconfRequestBType));

        // Verify the proof block number matches the target slot
        if (
            publicValues.proofBlockNumber
                != preconfRequestBType.blockspaceAllocation.targetSlot
        ) {
            revert TargetSlotDoesNotMatch();
        }

        // TODO: Verify the block hash

        // Verify the proof challenge ID matches the challenge ID
        if (keccak256(publicValues.signature) != keccak256(challenge.signature)) {
            revert ChallengeIdDoesNotMatch();
        }

        // Verify the proof commitment signer matches the challenge commitment signer
        if (publicValues.gatewayAddress != challenge.commitmentSigner) {
            revert CommitmentSignerDoesNotMatch();
        }

        openChallengeCount--;
        emit ChallengeFailed(id);
    }

    function _getSlotFromTimestamp(uint256 timestamp) internal view returns (uint256) {
        return (timestamp - parameterManager.genesisTimestamp())
            / parameterManager.slotTime();
    }
}
