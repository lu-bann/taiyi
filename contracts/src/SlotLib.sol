// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

library SlotLib {
    uint256 internal constant SLOT_TIME = 12;

    function getSlotFromTimestamp(uint256 timestamp, uint256 genesisTimestamp) internal pure returns (uint256) {
        return (timestamp - genesisTimestamp) / SLOT_TIME;
    }
}
