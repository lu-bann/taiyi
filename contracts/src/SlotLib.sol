// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

library SlotLib {
    uint256 internal constant SLOT_TIME = 12;
    uint256 internal constant ETH2_GENESIS_TIMESTAMP = 1_606_824_023;

    function getSlotFromTimestamp(uint256 timestamp) internal view returns (uint256) {
        return (timestamp - ETH2_GENESIS_TIMESTAMP) / SLOT_TIME;
    }
}

library SlotHelderLib {
    uint256 internal constant SLOT_TIME = 12;
    uint256 internal constant ETH2_GENESIS_TIMESTAMP = 1_606_824_023;

    function getSlotFromTimestamp(uint256 timestamp) internal view returns (uint256) {
        return (timestamp - ETH2_GENESIS_TIMESTAMP) / SLOT_TIME;
    }
}
