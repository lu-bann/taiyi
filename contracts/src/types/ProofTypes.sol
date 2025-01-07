// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Proof data for verifying anchor transaction inclusion
/// @dev Example of how anchor tx is used to locate target tx:
///      Block transactions: [tx0, tx1, anchorTx, tx3, tx4, targetTx, tx6]
///                                    ^index=2        ^
///                                                   targetTxIndex =
/// anchorTxIndex + positionDelta
///                                                   targetTxIndex = 2 +
/// (sequenceNum + bundleIndex)
///                                                    *sequenceNum from
/// PreconfRequestTypeA.sequenceNum
///                                                    *bundleIndex passed as
/// param to verifyFraudProof()
///                                                   targetTxIndex = 2 + (2 +
/// 1) = 5
/// @param inclusionBlockNumber Block number containing the anchor transaction
/// @param blockHeaderRLP RLP-encoded block header for verification
/// @param anchorTxIndex Index of the anchor transaction in the block
/// @param txMerkleProof Merkle proof demonstrating transaction inclusion
/// @param anchorTxRLP RLP-encoded anchor transaction data
struct AnchorTxProof {
    uint256 inclusionBlockNumber;
    bytes blockHeaderRLP;
    uint256 anchorTxIndex;
    bytes[] txMerkleProof;
    bytes anchorTxRLP;
}

/// @notice Represents a simplified Ethereum block header containing only fields
/// needed for verification
/// @dev This is a minimal version of the full Ethereum block header, with
/// unused fields commented out
/// @dev Field numbers correspond to their position in RLP encoding
/// @param parentHash Hash of the parent block (field 0)
/// @param stateRoot Root of the state trie (field 3)
/// @param transactionsRoot Root of the transactions trie (field 4)
/// @param number Block number (field 8)
/// @param timestamp Block timestamp in seconds since unix epoch (field 11)
/// @param baseFeePerGas Base fee per gas in wei, introduced in EIP-1559 (field
/// 15, optional)
struct BlockHeader {
    bytes32 parentHash; // 0
    // bytes32 uncleHash;        // 1
    // address coinbase; // 2
    bytes32 stateRoot; // 3
    bytes32 transactionsRoot; // 4
    // bytes32 receiptsRoot;     // 5
    // bytes logsBloom;         // 6
    // uint256 difficulty;       // 7
    uint256 number; // 8
    // uint256 gasLimit;        // 9
    // uint256 gasUsed;         // 10
    uint256 timestamp; // 11
    // bytes extraData;         // 12
    // bytes32 mixHash;         // 13
    // bytes8 nonce; // 14
    // Post-Merge fields
    uint256 baseFeePerGas; // 15 (optional)
        // bytes32 withdrawalsRoot;  // 16 (optional)
}
