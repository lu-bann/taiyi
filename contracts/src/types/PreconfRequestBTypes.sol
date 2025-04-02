// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @dev Block reservation for a preconfirmation request
/// @notice This struct represents a reservation for block space, supporting
/// both EIP-1559 and EIP-4844 blob transactions
/// @dev If blobCount > 0, this indicates a blob transaction request and
/// gasLimit will be ignored
/// @dev For 4844 transactions (blobCount > 0):
///      - gasLimit is ignored since blob transactions have their own gas
/// accounting
///      - The request is specifically for blob data inclusion rather than a
/// standard EIP-1559 transaction
/// @dev For 1559 transactions (blobCount == 0):
///      - gasLimit is enforced as normal for EIP-1559 transactions
/// @param gasLimit Gas limit for the preconf transaction (only used when
/// blobCount == 0)
/// @param sender The address initiating the preconfirmation request
/// @param recipient The address receiving the preconfirmation tip
/// @param deposit Amount deposited for making the reservation
/// @param tip Fee paid to the underwriter for their service
/// @param targetSlot Target block slot for the preconfirmation
/// @param blobCount Number of blobs in the transaction. If > 0, indicates a
/// blob transaction request
struct BlockspaceAllocation {
    uint256 gasLimit;
    address sender;
    address recipient;
    uint256 deposit;
    uint256 tip;
    uint256 targetSlot;
    uint256 blobCount;
}

/// @notice A preconfirmation request containing all necessary data for block
/// inclusion
/// @dev The lifecycle of a preconf request:
///      1. User submits request with blockspace allocation and their signature
///      2. Underwriter accepts and signs the request, creating
/// underwriterSignedBlockspaceAllocation
///      3. At target slot, user submits rawTx
///      4. Underwriter signs rawTx to create underwriterSignedRawTx before calling
/// `TaiyiCore.getTip`
/// @param blockspaceAllocation The requested block space allocation details
/// @param blockspaceAllocationSignature User's signature over the blockspace
/// allocation
/// @param underwriterSignedBlockspaceAllocation Underwriter's signature over `blockspaceAllocationSignature`
/// @param rawTx The raw transaction submitted by user at target slot
/// @param underwriterSignedRawTx Underwriter's signed version of the raw transaction
/// for inclusion
struct PreconfRequestBType {
    BlockspaceAllocation blockspaceAllocation;
    bytes blockspaceAllocationSignature;
    bytes underwriterSignedBlockspaceAllocation;
    bytes rawTx;
    bytes underwriterSignedRawTx;
}
