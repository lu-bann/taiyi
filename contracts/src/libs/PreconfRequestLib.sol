// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {
    BlockspaceAllocation, PreconfRequestBType
} from "../types/PreconfRequestBTypes.sol";

library PreconfRequestLib {
    /*//////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////*/

    bytes32 constant BLOCKSPACE_ALLOCATION_TYPEHASH = keccak256(
        "BlockspaceAllocation(uint256 gasLimit,address sender,address recipient,uint256 deposit,uint256 tip,uint256 targetSlot,uint256 blobCount)"
    );

    bytes32 constant PRECONF_REQUEST_B_TYPE_HASH = keccak256(
        "PreconfRequestBType(BlockspaceAllocation blockspaceAllocation,bytes blockspaceAllocationSignature,bytes gatewaySignedBlockspaceAllocation,bytes rawTx,bytes gatewaySignedRawTx)"
    );

    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

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

    function getBlockspaceAllocationHash(
        BlockspaceAllocation calldata blockspaceAllocation
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                getDomainSeparator(),
                _getBlockspaceAllocationHash(blockspaceAllocation)
            )
        );
    }

    function getPreconfRequestBTypeHash(PreconfRequestBType calldata preconfRequestBType)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                getDomainSeparator(),
                _getPreconfRequestBTypeHash(preconfRequestBType)
            )
        );
    }

    function _getPreconfRequestBTypeHash(PreconfRequestBType calldata preconfRequestBType)
        internal
        pure
        returns (bytes32)
    {
        bytes32 blockspaceAllocationHash =
            _getBlockspaceAllocationHash(preconfRequestBType.blockspaceAllocation);
        return keccak256(
            abi.encode(
                PRECONF_REQUEST_B_TYPE_HASH,
                blockspaceAllocationHash,
                preconfRequestBType.blockspaceAllocationSignature,
                preconfRequestBType.gatewaySignedBlockspaceAllocation,
                preconfRequestBType.rawTx,
                preconfRequestBType.gatewaySignedRawTx
            )
        );
    }

    function _getBlockspaceAllocationHash(
        BlockspaceAllocation calldata blockspaceAllocation
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                BLOCKSPACE_ALLOCATION_TYPEHASH,
                blockspaceAllocation.gasLimit,
                blockspaceAllocation.sender,
                blockspaceAllocation.recipient,
                blockspaceAllocation.deposit,
                blockspaceAllocation.tip,
                blockspaceAllocation.targetSlot,
                blockspaceAllocation.blobCount
            )
        );
    }
}
