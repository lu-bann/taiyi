// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { BlockReservation, PreconfTx, PreconfRequest, PreconfRequestTypeA } from "../interfaces/Types.sol";

library PreconfRequestLib {
    /*//////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////*/

    bytes32 constant TIP_TX_TYPEHASH = keccak256(
        "BlockReservation(uint256 gasLimit,address sender,address recipient,uint256 deposit,uint256 tip,uint256 nonce,uint256 targetSlot,uint256 blobCount)"
    );

    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function getDomainSeparator() public view returns (bytes32) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        return keccak256(
            abi.encode(
                PreconfRequestLib.EIP712_DOMAIN_TYPEHASH,
                // Contract name
                keccak256(bytes("TaiyiCore")),
                // Version
                keccak256(bytes("1.0")),
                // Chain ID
                chainId
            )
        );
    }

    function getPreconfRequestHash(PreconfRequest calldata preconfRequest) public view returns (bytes32) {
        bytes32 blockReservationHash = getBlockReservationHash(preconfRequest.blockReservation);
        bytes32 preconfTxHash = getPreconfTxHash(preconfRequest.preconfTx);
        return keccak256(
            abi.encodePacked(
                blockReservationHash,
                preconfTxHash,
                preconfRequest.blockReservationSignature,
                preconfRequest.preconfTxSignature
            )
        );
    }

    function getBlockReservationHash(BlockReservation calldata blockReservation) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), _getBlockReservationHash(blockReservation)));
    }

    function _getBlockReservationHash(BlockReservation calldata blockReservation) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TIP_TX_TYPEHASH,
                blockReservation.gasLimit,
                blockReservation.sender,
                blockReservation.recipient,
                blockReservation.deposit,
                blockReservation.tip,
                blockReservation.nonce,
                blockReservation.targetSlot,
                blockReservation.blobCount
            )
        );
    }

    function getPreconfRequestTypeAHash(PreconfRequestTypeA calldata preconfRequestTypeA)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("\x19\x01", getDomainSeparator(), _getPreconfRequestTypeAHash(preconfRequestTypeA))
        );
    }

    function _getPreconfRequestTypeAHash(PreconfRequestTypeA calldata request) public pure returns (bytes32) {
        return keccak256(abi.encode(request.txs, request.tipTx, request.slot, request.sequenceNum, request.signer));
    }

    function encodePreconfTx(PreconfTx calldata preconfTx) public pure returns (bytes memory) {
        return abi.encode(
            preconfTx.from, preconfTx.to, preconfTx.value, preconfTx.callData, preconfTx.blobHashes, preconfTx.nonce
        );
    }

    function getPreconfTxHash(PreconfTx calldata preconfTx) public pure returns (bytes32) {
        return keccak256(encodePreconfTx(preconfTx));
    }
}
