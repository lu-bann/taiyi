// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IInteractiveChallenger } from "./interfaces/IInteractiveChallenger.sol";
import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { ISP1Verifier } from "@sp1-contracts/ISP1Verifier.sol";

contract InteractiveChallenger is IInteractiveChallenger, Ownable {
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

    /// @inheritdoc IInteractiveChallenger
    function setVerifierGateway(address _verifierGateway) external onlyOwner {
        verifierGateway = _verifierGateway;
    }

    /// @inheritdoc IInteractiveChallenger
    function setInteractiveFraudProofVKey(bytes32 _interactiveFraudProofVKey)
        external
        onlyOwner
    {
        interactiveFraudProofVKey = _interactiveFraudProofVKey;
    }

    /// @inheritdoc IInteractiveChallenger
    function getChallenges() external view returns (Challenge[] memory) {
        revert("Not implemented");
    }

    /// @inheritdoc IInteractiveChallenger
    function getOpenChallenges() external view returns (Challenge[] memory) {
        revert("Not implemented");
    }

    /// @inheritdoc IInteractiveChallenger
    function getChallenge(bytes32 id) external view returns (Challenge memory) {
        revert("Not implemented");
    }

    /// @inheritdoc IInteractiveChallenger
    function createChallenge() external payable {
        revert("Not implemented");
    }

    /// @inheritdoc IInteractiveChallenger
    function resolveExpiredChallenge() external {
        revert("Not implemented");
    }

    /// @inheritdoc IInteractiveChallenger
    function defendWithProof(
        bytes32 id,
        bytes calldata proofValues,
        bytes calldata proofBytes
    )
        external
    {
        // TODO[Martin]: Define values we want to verify before calling the SP1 contract
        // TODO[Martin]: Define proofValues which we want to read onchain and which we want to pass in as function arguments

        // Verify the proof
        ISP1Verifier(verifierGateway).verifyProof(
            interactiveFraudProofVKey, proofValues, proofBytes
        );

        // TODO[Martin]: Define values we want to verify after calling the SP1 contract

        revert("Not implemented");
    }
}
