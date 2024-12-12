// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { AnchorTxProof, PreconfRequestTypeA } from "./interfaces/Types.sol";
import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import { SignatureVerificationLib } from "./libs/SignatureVerificationLib.sol";
import { PreconfRequestLib } from "./libs/PreconfRequestLib.sol";
import { RLPReaderLib } from "./libs/RLPReaderLib.sol";

/// @title TaiyiProofManager
/// @notice Manages fraud proofs for the Taiyi protocol
/// @dev Handles verification of transaction inclusion and signature proofs
contract TaiyiProofManager {
    using SignatureChecker for address;
    using SignatureVerificationLib for bytes;
    using SignatureVerificationLib for bytes32;
    using PreconfRequestLib for PreconfRequestTypeA;
    using RLPReaderLib for bytes;

    /// @notice Emitted when fraud is detected
    /// @param reporter Address that reported the fraud
    event FraudDetected(address indexed reporter);

    function verifyFraudProof(
        PreconfRequestTypeA calldata preconfReqTypeA,
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

        // Verify inclusion of the anchor transaction
        // _verifyAnchorTransaction(anchorTxProof, anchorTxRLP, blockHeaderRLP);

        // // Step 2: Verify the signature over PreconfRequestTypeA
        // address gatewaySigner = _verifyPreconfSignature(preconfReq);

        // // Step 3: Iterate over txs and verify their inclusion
        // _verifyTransactionsInclusion(preconfReq, blockHeaderRLP);

        // // If verifications pass, but the committed transactions are not included, it's fraud
        // // Handle fraud logic
        // emit FraudDetected(msg.sender);
    }

    // /// @dev Verifies that the anchor transaction is included in the block
    // /// @param anchorTxProof Merkle proof of anchor transaction inclusion
    // /// @param anchorTxRLP RLP encoded anchor transaction
    // /// @param blockHeaderRLP RLP encoded block header
    // function _verifyAnchorTransaction(
    //     bytes calldata anchorTxProof,
    //     bytes calldata anchorTxRLP,
    //     bytes calldata blockHeaderRLP
    // )
    //     internal
    //     view
    // {
    //     // ... implementation from above
    // }

    // /// @dev Verifies the signature on the preconfirmation request
    // /// @param preconfReq The preconfirmation request to verify
    // /// @return gatewaySigner The address that signed the request
    // function _verifyPreconfSignature(PreconfRequestTypeA calldata preconfReq)
    //     internal
    //     pure
    //     returns (address gatewaySigner)
    // {
    //     // ... implementation from above
    // }

    // /// @dev Verifies that all transactions in the request are included in the block
    // /// @param preconfReq The preconfirmation request containing transactions
    // /// @param blockHeaderRLP RLP encoded block header
    // function _verifyTransactionsInclusion(
    //     PreconfRequestTypeA calldata preconfReq,
    //     bytes calldata blockHeaderRLP
    // )
    //     internal
    //     view
    // {
    //     // ... implementation from above
    // }

    // /// @dev Extracts the transaction index from RLP encoded transaction data
    // /// @param txRLP RLP encoded transaction
    // /// @return The index of the transaction in the block
    // function _getTransactionIndex(bytes memory txRLP) internal pure returns (uint256) {
    //     // Implement logic to extract transaction index from txRLP
    //     // Placeholder implementation
    //     return 0;
    // }
}
