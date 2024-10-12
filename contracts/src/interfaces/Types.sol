// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @dev Tip transaction a user sends to the preconfer
/// from - the address of the user
/// to - the address of the preconfer
/// prePay - is the payment a preconfer could receive after calling the exhaust function
/// afterPay is the payment a preconfer could receive after successfully executing the transaction by calling the
/// settleRequest function
/// nonce - prevents double spend
/// target_slot - the slot of the target preconf transaction
struct TipTx {
    uint256 gasLimit;
    address from;
    address to;
    uint256 prePay;
    uint256 afterPay;
    uint256 nonce;
    uint256 targetSlot;
}

/// @dev A transaction that the user want to execute for preconfirmation, like normal transaction
/// from - the address of the sender
/// to - the address of the recipient
/// value - the value of the transaction
/// callData - the calldata of the transaction
/// callGasLimit - the gas limit of the transaction
/// nonce - prevents double spend
/// preconfTxSignature - the signature of the preconf transaction
struct PreconfTx {
    address from;
    address to;
    uint256 value;
    bytes callData;
    uint256 callGasLimit;
    uint256 nonce;
    bytes signature;
}

struct PreconfRequest {
    TipTx tipTx;
    PreconfTx preconfTx;
    bytes tipTxSignature;
    bytes preconferSignature;
    bytes preconfReqSignature;
}

enum PreconfRequestStatus {
    NonInitiated, // default value
    Exhausted,
    Executed,
    Collected
}
