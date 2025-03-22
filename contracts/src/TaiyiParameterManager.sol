// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiParameterManager } from "./interfaces/ITaiyiParameterManager.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

contract TaiyiParameterManager is
    ITaiyiParameterManager,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    /// @dev The bond required to open a challenge.
    uint256 public challengeBond;

    /// @dev The maximum duration a challenge can be open for.
    /// After this period, the challenge is considered undefended or successful.
    uint256 public challengeMaxDuration;

    /// @dev The challenge creation window.
    uint256 public challengeCreationWindow;

    /// @dev The genesis timestamp of the chain.
    uint256 public genesisTimestamp;

    /// @dev The slot time of the chain.
    uint256 public slotTime;

    /// @dev Total storage slots: 50
    uint256[50] private __gap;

    /// @notice The initializer for the ParameterManager contract.
    function initialize(
        address _owner,
        uint256 _challengeBond,
        uint256 _challengeMaxDuration,
        uint256 _challengeCreationWindow,
        uint256 _genesisTimestamp,
        uint256 _slotTime
    )
        public
        initializer
    {
        __Ownable_init(_owner);

        challengeBond = _challengeBond;
        challengeMaxDuration = _challengeMaxDuration;
        challengeCreationWindow = _challengeCreationWindow;
        genesisTimestamp = _genesisTimestamp;
        slotTime = _slotTime;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    /// @inheritdoc ITaiyiParameterManager
    function setChallengeBond(uint256 _challengeBond) external onlyOwner {
        challengeBond = _challengeBond;
    }

    /// @inheritdoc ITaiyiParameterManager
    function setChallengeMaxDuration(uint256 _challengeMaxDuration) external onlyOwner {
        challengeMaxDuration = _challengeMaxDuration;
    }

    /// @inheritdoc ITaiyiParameterManager
    function setChallengeCreationWindow(uint256 _challengeCreationWindow)
        external
        onlyOwner
    {
        challengeCreationWindow = _challengeCreationWindow;
    }

    /// @inheritdoc ITaiyiParameterManager
    function setGenesisTimestamp(uint256 _genesisTimestamp) external onlyOwner {
        genesisTimestamp = _genesisTimestamp;
    }

    /// @inheritdoc ITaiyiParameterManager
    function setSlotTime(uint256 _slotTime) external onlyOwner {
        slotTime = _slotTime;
    }
}
