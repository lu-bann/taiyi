// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { RLPItem, RLPReaderLib } from "../libs/RLPReaderLib.sol";
import { BlockHeader } from "../interfaces/Types.sol";

/// @title Decoder
/// @notice Library for decoding RLP-encoded Ethereum block headers
library Decoder {
    using RLPReaderLib for bytes;
    using RLPReaderLib for RLPItem;

    /// @notice Decodes an RLP-encoded block header into a BlockHeader struct
    /// @param rlpBytes The RLP-encoded block header bytes
    /// @return header The decoded BlockHeader struct
    function decodeBlockHeader(bytes memory rlpBytes) internal pure returns (BlockHeader memory header) {
        RLPItem item = rlpBytes.toRLPItem();
        RLPItem[] memory items = item.readList();

        require(items.length >= 15, "BlockHeaderDecoder: Invalid block header RLP");

        header = BlockHeader({
            parentHash: items[0].readBytes32(),
            //uncleHash: items[1].readBytes32(),
            // coinbase: address(uint160(uint256(items[2].readBytes32()))),
            stateRoot: items[3].readBytes32(),
            transactionsRoot: items[4].readBytes32(),
            //receiptsRoot: items[5].readBytes32(),
            //logsBloom: items[6].readBytes(),
            //difficulty: items[7].readUint256(),
            number: items[8].readUint256(),
            //gasLimit: items[9].readUint256(),
            //gasUsed: items[10].readUint256(),
            timestamp: items[11].readUint256(),
            //extraData: items[12].readBytes(),
            //mixHash: items[13].readBytes32(),
            // nonce: bytes8(items[14].readBytes()),
            // Handle optional post-Merge fields
            baseFeePerGas: items.length > 15 ? items[15].readUint256() : 0
        });
        //withdrawalsRoot: items.length > 16 ? items[16].readBytes32() : bytes32(0)
    }
}
