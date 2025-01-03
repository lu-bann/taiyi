// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

library SlotLib {
    uint256 internal constant SLOT_TIME = 12;

    /**
     * @notice Calculates the slot number from a given timestamp.
     * @dev This function calculates the slot number based on the provided
     * timestamp and genesis timestamp.
     * @param timestamp The timestamp to calculate the slot number from.
     * @param genesisTimestamp The genesis timestamp of the system.
     * @return The slot number corresponding to the given timestamp.
     */
    function getSlotFromTimestamp(
        uint256 timestamp,
        uint256 genesisTimestamp
    )
        internal
        pure
        returns (uint256)
    {
        require(timestamp >= genesisTimestamp, "Invalid timestamp");
        return (timestamp - genesisTimestamp) / SLOT_TIME;
    }
}
