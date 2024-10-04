// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TipTx, PreconfTx, PreconfRequest } from "../interfaces/Types.sol";

library PreconfRequestLib {
    /*//////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////*/

    bytes32 constant TIP_TX_TYPEHASH = keccak256(
        "TipTx(uint256 gasLimit,address from,address to,uint256 prePay,uint256 afterPay,uint256 nonce,uint256 target_slot)"
    );

    bytes32 constant INCLUSION_META_TYPEHASH = keccak256("InclusionMeta(uint256 startingBlockNumber)");

    bytes32 constant ORDERING_META_TYPEHASH = keccak256("OrderingMeta(uint256 txCount,uint256 index)");

    bytes32 constant PRECONF_CONDITIONS_TYPEHASH = keccak256(
        abi.encodePacked(
            "PreconfConditions(",
            "InclusionMeta inclusionMetaData,",
            "OrderingMeta orderingMetaData,",
            "uint256 blockNumber",
            ")"
        )
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
                keccak256(bytes("LubanCore")),
                // Version
                keccak256(bytes("1.0")),
                // Chain ID
                chainId
            )
        );
    }

    function getPreconfRequestHash(PreconfRequest calldata preconfRequest) public view returns (bytes32) {
        bytes32 tipTxHash = getTipTxHash(preconfRequest.tipTx);
        bytes32 preconfTxHash = getPreconfTxHash(preconfRequest.preconfTx);
        return keccak256(
            abi.encodePacked(tipTxHash, preconfTxHash, preconfRequest.tipTxSignature, preconfRequest.preconferSignature)
        );
    }

    function getTipTxHash(TipTx calldata tipTx) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), _getTipTxHash(tipTx)));
    }

    function _getTipTxHash(TipTx calldata tipTx) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TIP_TX_TYPEHASH,
                tipTx.gasLimit,
                tipTx.from,
                tipTx.to,
                tipTx.prePay,
                tipTx.afterPay,
                tipTx.nonce,
                tipTx.target_slot
            )
        );
    }

    function getPreconfTxHash(PreconfTx calldata preconfTx) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                preconfTx.from,
                preconfTx.to,
                preconfTx.value,
                preconfTx.callData,
                preconfTx.callGasLimit,
                preconfTx.nonce
            )
        );
    }
}
