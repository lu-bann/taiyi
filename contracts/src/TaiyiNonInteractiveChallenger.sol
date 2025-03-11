// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiNonInteractiveChallenger } from
    "./interfaces/ITaiyiNonInteractiveChallenger.sol";
import { PreconfRequestAType } from "./types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "./types/PreconfRequestBTypes.sol";
import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { ISP1Verifier } from "@sp1-contracts/ISP1Verifier.sol";

contract TaiyiNonInteractiveChallenger is ITaiyiNonInteractiveChallenger, Ownable {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifierGateway;

    /// @notice The verification key for the interactive fraud proof program.
    /// @dev When the verification key changes a new version of the contract must be deployed.
    bytes32 public nonInteractiveFraudProofVKey;

    constructor(
        address _initialOwner,
        address _verifierGateway,
        bytes32 _nonInteractiveFraudProofVKey
    )
        Ownable(_initialOwner)
    {
        verifierGateway = _verifierGateway;
        nonInteractiveFraudProofVKey = _nonInteractiveFraudProofVKey;
    }

    /// @inheritdoc ITaiyiNonInteractiveChallenger
    function setVerifierGateway(address _verifierGateway) external onlyOwner {
        verifierGateway = _verifierGateway;
    }

    /// @inheritdoc ITaiyiNonInteractiveChallenger
    function setNonInteractiveFraudProofVKey(bytes32 _nonInteractiveFraudProofVKey)
        external
        onlyOwner
    {
        nonInteractiveFraudProofVKey = _nonInteractiveFraudProofVKey;
    }

    /// @inheritdoc ITaiyiNonInteractiveChallenger
    function getChallenges() external view returns (Challenge[] memory) {
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiNonInteractiveChallenger
    function getChallenge(bytes32 id) external view returns (Challenge memory) {
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiNonInteractiveChallenger
    function proveAType(
        PreconfRequestAType calldata preconfRequestAType,
        bytes calldata signature,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
        payable
    {
        // ABI Encode preconfRequestAType needed for the challenge struct

        // Verify the proof
        ISP1Verifier(verifierGateway).verifyProof(
            nonInteractiveFraudProofVKey, proofValues, proofBytes
        );

        revert("Not implemented");

        // Emit event for successful challenge
        // emit ChallengeSucceded(id, challenger, commitmentSigner);
    }

    /// @inheritdoc ITaiyiNonInteractiveChallenger
    function proveBType(
        PreconfRequestBType calldata preconfRequestBType,
        bytes calldata signature,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
        payable
    {
        // ABI Encode preconfRequestBType needed for the challenge struct

        // Verify the proof
        ISP1Verifier(verifierGateway).verifyProof(
            nonInteractiveFraudProofVKey, proofValues, proofBytes
        );

        revert("Not implemented");

        // Emit event for successful challenge
        // emit ChallengeSucceded(id, challenger, commitmentSigner);
    }
}
