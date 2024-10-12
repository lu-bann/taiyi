// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequest } from "./Types.sol";

interface ITaiyiChallengeManager {
    function challengeRequests(PreconfRequest[] calldata preconfReqs) external;
}
