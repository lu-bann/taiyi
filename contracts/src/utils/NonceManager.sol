// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/**
 * nonce management functionality
 */
abstract contract NonceManager {
    /**
     * The next valid sequence number for a given nonce key.
     */
    mapping(address => uint256) private tipNonceSequenceNumber;
    mapping(address => uint256) private preconfNonceSequenceNumber;

    function getTipNonce(address sender) public view returns (uint256 nonce) {
        return tipNonceSequenceNumber[sender];
    }

    // allow an account to manually increment its own tip nonce.
    function incrementTipNonce(address sender) internal {
        tipNonceSequenceNumber[sender]++;
    }

    function getPreconfNonce(address sender) public view returns (uint256 nonce) {
        return preconfNonceSequenceNumber[sender];
    }

    // allow an account to manually increment its own preconf nonce.
    function incrementPreconfNonce(address sender) internal {
        preconfNonceSequenceNumber[sender]++;
    }
}
