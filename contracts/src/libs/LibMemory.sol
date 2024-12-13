// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice A dedicated memory pointer type
/// @dev It is unrealistic that a pointer would ever be larger than 24 bits (16777.215KB max)
///      given the 30_000_000 block gas limit on L1.
type MemoryPointer is uint24;

/// @notice A dedicated type for an RLP item.
/// @dev The RLP item contains two pieces of information:
/// ┌───────────┬────────────────┐
/// │   Bits    │  Description   │
/// ├───────────┼────────────────┤
/// │ [0, 24)   │ Memory Pointer │
/// │ [24, 256) │ Length of Item │
/// └───────────┴────────────────┘
type RLPItem is bytes32;

using RLPItemLib for RLPItem global;

library RLPItemLib {
    /// @notice Extracts the memory pointer from an RLPItem
    /// @param item The RLPItem
    /// @return ptr The memory pointer
    function ptr(RLPItem item) internal pure returns (uint256 ptr) {
        // Mask the lower 24 bits to get the pointer
        ptr = uint256(RLPItem.unwrap(item)) & 0xFFFFFF;
    }

    /// @notice Extracts the length from an RLPItem
    /// @param item The RLPItem
    /// @return length The length of the item
    function length(RLPItem item) internal pure returns (uint256 length) {
        // Shift right by 24 bits to get the length
        length = uint256(RLPItem.unwrap(item)) >> 24;
    }
}

/// @notice RLP item types.
/// @custom:value DATA_ITEM Represents an RLP data item (NOT a list).
/// @custom:value LIST_ITEM Represents an RLP list item.
enum RLPItemType {
    DATA_ITEM,
    LIST_ITEM
}

/// @title LibMemory
/// @notice This library contains utility functions for manipulating and interacting
///         with memory directly.
/// @custom:attribution Based on
/// https://github.com/clabby/substratum/blob/4028bf1b121d9127c1c27d2a4feda3e44d3c9239/src/lib/LibMemory.sol
library LibMemory {
    /// @notice Copies the bytes from a memory location. (wen mcopy?)
    /// @param _src    Pointer to the location to read from.
    /// @param _offset Offset to start reading from.
    /// @param _length Number of bytes to read.
    /// @return _out Copied bytes.
    /// @dev This function can potentially cause memory safety issues if it is important that the final word of the
    /// copied
    ///      bytes is not partially dirty. This is because the final word is not cleaned after copying. For hashing
    /// operations,
    ///      this is not an issue because the only bytes that are included in the preimage are within the bounds of the
    /// length
    ///      of the dynamic type.
    function mcopy(MemoryPointer _src, uint256 _offset, uint256 _length) public pure returns (bytes memory _out) {
        assembly ("memory-safe") {
            switch _length
            case 0x00 {
                // Assign `_out` to the zero offset
                _out := 0x60
            }
            default {
                // Assign `_out` to the free memory pointer.
                _out := mload(0x40)

                // Compute the starting offset of the source bytes
                let src := add(_src, _offset)
                // Compute the destination offset of the copied bytes
                let dest := add(_out, 0x20)

                // Copy the bytes
                let offset := 0x00
                for { } lt(offset, _length) { offset := add(offset, 0x20) } {
                    mstore(add(dest, offset), mload(add(src, offset)))
                }

                // Assign the length of the copied bytes
                mstore(_out, _length)
                // Update the free memory pointer
                mstore(0x40, and(add(_out, add(offset, 0x3F)), not(0x1F)))
            }
        }
    }

    /// @notice Copies the bytes from a memory location to another memory location directly.
    /// @param _src    Pointer to the location to read from.
    /// @param _dest   Pointer to the location to write to.
    /// @param _length Number of bytes to copy starting from the `_src` pointer.
    function mcopyDirect(MemoryPointer _src, MemoryPointer _dest, uint256 _length) internal view {
        assembly ("memory-safe") {
            // Copy the bytes using the identity precompile.
            pop(staticcall(gas(), 0x04, _src, _length, _dest, _length))
        }
    }
}
