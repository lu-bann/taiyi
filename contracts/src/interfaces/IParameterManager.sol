// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface IParameterManager {
    /// @notice Get the challenge bond required to open a challenge.
    function getChallengeBond() external view returns (uint256);

    /// @notice Get the maximum duration a challenge can be open for.
    function getChallengeMaxDuration() external view returns (uint256);

    /// @notice Set the challenge bond.
    /// @param _challengeBond The bond required to open a challenge.
    function setChallengeBond(uint256 _challengeBond) external;

    /// @notice Set the challenge maxiumum duration.
    /// @param _challengeMaxDuration The maximum duration of a challenge.
    function setChallengeMaxDuration(uint256 _challengeMaxDuration) external;
}
