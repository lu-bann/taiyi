// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface ITaiyiParameterManager {
    /// @notice Get the challenge bond required to open a challenge.
    function challengeBond() external view returns (uint256);

    /// @notice Get the maximum duration a challenge can be open for.
    function challengeMaxDuration() external view returns (uint256);

    /// @notice Get the challenge creation window how many blocks can pass before a challenge can be created.
    function challengeCreationWindow() external view returns (uint256);

    /// @notice Get the genesis timestamp of the chain.
    function genesisTimestamp() external view returns (uint256);

    /// @notice Get the slot time of the chain.
    function slotTime() external view returns (uint256);

    /// @notice Set the challenge bond.
    /// @param _challengeBond The bond required to open a challenge.
    function setChallengeBond(uint256 _challengeBond) external;

    /// @notice Set the challenge maxiumum duration.
    /// @param _challengeMaxDuration The maximum duration of a challenge.
    function setChallengeMaxDuration(uint256 _challengeMaxDuration) external;

    /// @notice Set the challenge creation window.
    /// @param _challengeCreationWindow The challenge creation window.
    function setChallengeCreationWindow(uint256 _challengeCreationWindow) external;

    /// @notice Set the genesis timestamp.
    /// @param _genesisTimestamp The genesis timestamp.
    function setGenesisTimestamp(uint256 _genesisTimestamp) external;

    /// @notice Set the slot time.
    /// @param _slotTime The slot time.
    function setSlotTime(uint256 _slotTime) external;
}
