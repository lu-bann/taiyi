// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice A preconfirmation request type A containing raw transactions and tip payment
/// @param txs Array of raw transactions (RLP-encoded)
/// @param tipTx RLP-encoded ETH transfer transaction for tip payment
/// @param slot Target slot number
/// @param sequenceNum Index of the first transaction in txs within the constraint bundle. The anchor transaction
///        has index 0, so sequenceNum == 1 means this is the first bundle after the anchor transaction.
///        Example bundle layout:
///        [anchor tx (0)] | [tx0,tx1,tx2 (1)] | [tx3,tx4 (4)] | [tx5 (6)]
///                         ^ sequenceNum=1      ^ sequenceNum=4   ^ sequenceNum=6
/// @param signer The address that signed the request
struct PreconfRequestTypeA {
    bytes[] txs;
    bytes tipTx;
    uint64 slot;
    uint64 sequenceNum;
    address signer;
}

/// @dev Block reservation for a preconfirmation request. If blobCount > 0, it indicates a blob transaction request
/// gasLimit - gas limit for the preconf transaction
/// sender - the address initiating the preconfirmation request
/// recipient - the address receiving the preconfirmation tip
/// deposit - amount deposited for making the reservation
/// tip - fee paid to the preconfer for their service
/// nonce - prevents double spend attacks
/// targetSlot - target block slot for the preconfirmation
/// blobCount - number of blobs in the transaction
struct BlockReservation {
    uint256 gasLimit;
    address sender;
    address recipient;
    uint256 deposit;
    uint256 tip;
    uint256 nonce;
    uint256 targetSlot;
    uint256 blobCount;
}

/// @notice Proof data for verifying anchor transaction inclusion
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

/// @dev A transaction that the user wants to execute for preconfirmation, like normal transaction
/// from - the address of the sender
/// to - the address of the function to be called
/// value - the value to be transferred
/// callData - the calldata of the transaction
/// nonce - prevents double spend
/// blobHashes - array of blob hashes for blob transactions
/// signature - the signature of the preconf transaction
struct PreconfTx {
    address from;
    address to;
    uint256 value;
    bytes callData;
    uint256 nonce;
    bytes32[] blobHashes;
    bytes signature;
}

struct PreconfRequest {
    BlockReservation blockReservation;
    PreconfTx preconfTx;
    bytes blockReservationSignature;
    bytes preconferSignature;
    bytes preconfTxSignature;
}

enum PreconfRequestStatus {
    NonInitiated, // default value
    Exhausted,
    Executed,
    Collected
}
