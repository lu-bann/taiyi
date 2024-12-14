// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { AnchorTxProof, PreconfRequestTypeA, BlockHeader } from "./interfaces/Types.sol";
import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import { SignatureVerificationLib } from "./libs/SignatureVerificationLib.sol";
import { PreconfRequestLib } from "./libs/PreconfRequestLib.sol";
import { RLPReaderLib } from "./libs/RLPReaderLib.sol";
import { RLPWriterLib } from "./libs/RLPWriterLib.sol";
import { MerkleTrie } from "./libs/MerkleTrie.sol";
import { Decoder } from "./libs/Decoder.sol";

/// @title TaiyiProofManager
/// @notice Manages fraud proofs for the Taiyi protocol
/// @dev Handles verification of transaction inclusion and signature proofs
contract TaiyiProofManager {
    using SignatureChecker for address;
    using SignatureVerificationLib for bytes;
    using SignatureVerificationLib for bytes32;
    using PreconfRequestLib for PreconfRequestTypeA;
    using RLPReaderLib for bytes;
    using RLPWriterLib for uint256;
    using Decoder for bytes;

    /// @notice Emitted when fraud is detected
    /// @param reporter Address that reported the fraud
    event FraudDetected(address indexed reporter);

    /// @notice Emitted when a signature is verified
    /// @param signer Address that signed the message
    event SignatureVerified(address indexed signer);

    /// @notice Emitted when an anchor transaction is verified
    /// @param anchorTxIndex Index of the anchor transaction
    /// @param blockNumber Block number containing the anchor tx
    event AnchorTxVerified(uint256 indexed anchorTxIndex, uint256 indexed blockNumber);

    /// @notice Emitted when a target transaction is verified
    /// @param targetTxIndex Index of the target transaction
    /// @param blockNumber Block number containing the target tx
    event TargetTxVerified(uint256 indexed targetTxIndex, uint256 indexed blockNumber);

    /// @notice Verifies a fraud proof by verifying the PreconfRequest signatures and transaction inclusion using merkle
    /// proofs
    /// @dev Proof verification flow:
    /// 1. Verify signature on PreconfRequestTypeA
    /// 2. Verify anchor tx inclusion in block using merkle proof
    /// 3. Calculate target tx index relative to anchor tx
    /// 4. Verify target tx inclusion using merkle proof
    ///
    /// @dev Constraint bundle layout example:
    /// [anchor tx (0)] | [tx0,tx1,tx2 (1)] | [tx3,tx4 (4)] | [tx5 (6)]
    ///                   ^ sequenceNum=1      ^ sequenceNum=4   ^ sequenceNum=6
    ///
    /// Target tx index calculation:
    ///     targetTxIndex = anchorTxIndex + positionDelta
    ///     where positionDelta = sequenceNum + bundleIndex
    ///
    /// Example:
    /// - anchorTxIndex = 5 (position in block)
    /// - sequenceNum = 1 (first bundle after anchor)
    /// - bundleIndex = 2 (third tx in bundle)
    /// - positionDelta = 1 + 2 = 3
    /// - targetTxIndex = 5 + 3 = 8 (final position in block)
    ///
    /// @param preconfReqTypeA The preconf request containing txs and metadata
    /// @param bundleIndex Index of target tx within its bundle
    /// @param preconfReqSignature Signature over the preconf request
    /// @param anchorTxProof Proof of anchor tx inclusion in block
    /// @param targetTxMerkleProofs Merkle proofs for target tx inclusion
    function verifyFraudProof(
        PreconfRequestTypeA calldata preconfReqTypeA,
        uint256 bundleIndex,
        bytes calldata preconfReqSignature,
        AnchorTxProof calldata anchorTxProof,
        bytes[] calldata targetTxMerkleProofs
    )
        external
    {
        // Verify the signature over PreconfRequestTypeA
        preconfReqTypeA.getPreconfRequestTypeAHash().verifySignature(
            preconfReqTypeA.signer, preconfReqSignature, "signature verification failed"
        );
        emit SignatureVerified(preconfReqTypeA.signer);

        uint64 inclusionBlockNumber = preconfReqTypeA.slot;
        bytes32 inclusionBlockHash = blockhash(inclusionBlockNumber);
        require(inclusionBlockHash != bytes32(0), "inclusion block too old");

        require(
            inclusionBlockHash == keccak256(anchorTxProof.blockHeaderRLP),
            "block hash mismatch between PreconfRequestTypeA and AnchorTxProof"
        );

        BlockHeader memory blockHeader = anchorTxProof.blockHeaderRLP.decodeBlockHeader();
        bytes memory merkleLeaf = anchorTxProof.anchorTxIndex.writeUint();

        bool anchorTxExists = MerkleTrie.verifyInclusionProof(
            merkleLeaf, anchorTxProof.anchorTxRLP, anchorTxProof.txMerkleProof, blockHeader.transactionsRoot
        );

        require(anchorTxExists, "anchor transaction not included");
        emit AnchorTxVerified(anchorTxProof.anchorTxIndex, inclusionBlockNumber);

        // Calculate positionDelta to the anchor transaction
        uint256 positionDelta = preconfReqTypeA.sequenceNum + bundleIndex;

        // Compute target transaction index
        uint256 targetTxIndex = anchorTxProof.anchorTxIndex + positionDelta;

        // Retrieve the transaction at targetTxIndex
        bytes memory targetMerkleLeaf = targetTxIndex.writeUint();

        // Retrieve the RLP encoded transaction at targetTxIndex in the constraint bundle
        bytes memory targetTxRLP = preconfReqTypeA.bundle.transactions[targetTxIndex];

        // Verify the inclusion of the target transaction in the block's transaction merkle trie
        bool targetTxExists = MerkleTrie.verifyInclusionProof(
            targetMerkleLeaf, targetTxRLP, targetTxMerkleProofs, blockHeader.transactionsRoot
        );

        require(targetTxExists, "target transaction not included");

        // Todo: verify the transaction sponsorship. See [Fraud Proof for Gas Sponsorship
        // secion](https://github.com/lu-bann/taiyi/issues/283)
        // Todo: slash the gateway/validator, in this case signer of the PreconfRequestTypeA
    }
}
