// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiInteractiveChallenger } from "./interfaces/ITaiyiInteractiveChallenger.sol";
import { PreconfRequestAType } from "./types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "./types/PreconfRequestBTypes.sol";
import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { ISP1Verifier } from "@sp1-contracts/ISP1Verifier.sol";

contract TaiyiInteractiveChallenger is ITaiyiInteractiveChallenger, Ownable {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifierGateway;

    /// @notice The verification key for the interactive fraud proof program.
    /// @dev When the verification key changes a new version of the contract must be deployed.
    bytes32 public interactiveFraudProofVKey;

    constructor(
        address _initialOwner,
        address _verifierGateway,
        bytes32 _interactiveFraudProofVKey
    )
        Ownable(_initialOwner)
    {
        verifierGateway = _verifierGateway;
        interactiveFraudProofVKey = _interactiveFraudProofVKey;
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
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function getOpenChallenges() external view returns (Challenge[] memory) {
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function getChallenge(bytes32 id) external view returns (Challenge memory) {
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function createChallengeAType(PreconfRequestAType calldata _preconfRequestAType)
        external
        payable
    {
        // ABI Encode preconfRequestAType needed for the challenge struct
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function createChallengeBType(PreconfRequestBType calldata _preconfRequestBType)
        external
        payable
    {
        // ABI Encode preconfRequestBType needed for the challenge struct
        revert("Not implemented");
    }

    /// @inheritdoc ITaiyiInteractiveChallenger
    function resolveExpiredChallenge(bytes32 id) external {
        // Checks:
        // 1. The challenge must exist
        // 2. The challenge must be open (not failed or succeeded)
        // 3. The challenge must be expired

        revert("Not implemented");
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

        // Checks:
        // 1. The challenge must exist
        // 2. The challenge must be open (not failed or succeeded)
        // 3. The challenge must not be expired

        // Verify the proof
        ISP1Verifier(verifierGateway).verifyProof(
            interactiveFraudProofVKey, proofValues, proofBytes
        );

        revert("Not implemented");

        emit ChallengeSucceded(id);
    }
}
