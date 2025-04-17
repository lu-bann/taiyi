// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice A preconfirmation request type A containing raw transactions and tip
/// payment
/// @param txs Array of raw transactions (RLP-encoded)
/// @param tipTx RLP-encoded ETH transfer transaction for tip payment
/// @param slot Target slot number
/// @param sequenceNum Index of the first transaction in txs within the
/// constraint bundle. The anchor transaction
///        has index 0, so sequenceNum == 1 means this is the first bundle after
/// the anchor transaction.
///        Example bundle layout:
///        [anchor tx (0)] | [tx0,tx1,tx2 (1)] | [tx3,tx4 (4)] | [tx5 (6)]
///                         ^ sequenceNum=1      ^ sequenceNum=4   ^
/// sequenceNum=6
/// @param signer The address that signed the request
struct PreconfRequestAType {
    string[] txs;
    string tipTx;
    uint256 slot;
    uint256 sequenceNum;
    address signer;
}
