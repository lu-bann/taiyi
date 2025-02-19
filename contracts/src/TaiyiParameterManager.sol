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

    /// @dev The blockhash lookback window.
    uint256 public blockhashLookback;

    /// @dev Total storage slots: 50
    uint256[50] private __gap;

    /// @notice The initializer for the ParameterManager contract.
    function initialize(
        address _owner,
        uint256 _challengeBond,
        uint256 _challengeMaxDuration,
        uint256 _blockhashLookback
    )
        public
        initializer
    {
        __Ownable_init(_owner);

        challengeBond = _challengeBond;
        challengeMaxDuration = _challengeMaxDuration;
        blockhashLookback = _blockhashLookback;
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
    function setBlockhashLookback(uint256 _blockhashLookback) external onlyOwner {
        blockhashLookback = _blockhashLookback;
    }
}
