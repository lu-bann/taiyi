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

    function verifyFraudProof(
        PreconfRequestTypeA calldata preconfReqTypeA,
        uint256 bundleIndex,
        bytes calldata preconfReqSignature,
        AnchorTxProof calldata anchorTxProof
    )
        external
    {
        // Verify the signature over PreconfRequestTypeA
        preconfReqTypeA.getPreconfRequestTypeAHash().verifySignature(
            preconfReqTypeA.signer, preconfReqSignature, "signature verification failed"
        );

        uint64 inclusionBlockNumber = preconfReqTypeA.slot;
        bytes32 inclusionBlockHash = blockhash(inclusionBlockNumber);
        require(inclusionBlockHash != bytes32(0), "inclusion block too old");

        require(
            inclusionBlockHash == keccak256(anchorTxProof.blockHeaderRLP),
            "block hash mismatch between PreconfRequestTypeA and AnchorTxProof"
        );

        BlockHeader memory blockHeader = anchorTxProof.blockHeaderRLP.decodeBlockHeader();
        bytes memory merkleLeaf = anchorTxProof.anchorTxIndex.writeUint();

        bool anchorTxExists=
            MerkleTrie.verifyInclusionProof(merkleLeaf, anchorTxProof.anchorTxRLP, anchorTxProof.txMerkleProof, blockHeader.transactionsRoot);

        require(anchorTxExists, "anchor transaction not included");

        // Calculate positionDelta to the anchor transaction
        uint256 positionDelta = preconfReqTypeA.sequenceNum + bundleIndex;

        // Compute target transaction index
        uint256 targetTxIndex = anchorTxProof.anchorTxIndex + positionDelta;

        // Retrieve the transaction at targetTxIndex
        bytes memory targetMerkleLeaf = targetTxIndex.writeUint();

        (bool targetTxExists, bytes memory targetTxRLP) = MerkleTrie.get(targetMerkleLeaf, blockHeader.transactionsRoot);

        // Retrieve the transaction from PreconfRequestTypeA
        bytes memory preconfTxRLP = preconfReqTypeA.txs[bundleIndex];

        // Check for non-inclusion
        if (targetTxExists) {
            // If the transaction exists, compare it with the expected transaction
            if (keccak256(targetTxRLP) == keccak256(preconfTxRLP)) {
                // Transaction was included, fraud not detected
                revert("Transaction was included in the block");
            } else {
                // Transaction exists but does not match, fraud detected
                emit FraudDetected(msg.sender);
            }
        } else {
            // Transaction does not exist, fraud detected
            emit FraudDetected(msg.sender);
        }
    }
}
