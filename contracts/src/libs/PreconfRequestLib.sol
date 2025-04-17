// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {
    BlockspaceAllocation, PreconfRequestBType
} from "../types/PreconfRequestBTypes.sol";

import { PreconfRequestAType } from "../types/PreconfRequestATypes.sol";

library PreconfRequestLib {
    /*//////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////*/

    bytes32 constant BLOCKSPACE_ALLOCATION_TYPEHASH = keccak256(
        "BlockspaceAllocation(uint256 gasLimit,address sender,address recipient,uint256 deposit,uint256 tip,uint256 targetSlot,uint256 blobCount)"
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
                EIP712_DOMAIN_TYPEHASH,
                // Contract name
                keccak256("TaiyiCore"),
                // Version
                keccak256("1.0"),
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
                keccak256(
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
                )
            )
        );
    }

    function getPreconfRequestBTypeHash(PreconfRequestBType calldata preconfRequestBType)
        public
        view
        returns (bytes32)
    {
        bytes32 blockspaceAllocationHash =
            getBlockspaceAllocationHash(preconfRequestBType.blockspaceAllocation);

        return keccak256(
            abi.encodePacked(blockspaceAllocationHash, preconfRequestBType.rawTx)
        );
    }

    function getPreconfRequestATypeHash(PreconfRequestAType calldata preconfRequestAType)
        public
        view
        returns (bytes32)
    {
        uint256 chainId;

        assembly {
            chainId := chainid()
        }

        return keccak256(
            abi.encode(
                preconfRequestAType.tipTx,
                preconfRequestAType.txs,
                uint256(preconfRequestAType.slot),
                uint256(preconfRequestAType.sequenceNum),
                preconfRequestAType.signer,
                chainId
            )
        );
    }
}
