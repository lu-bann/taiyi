// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequest } from "./PreconfRequest.sol";

interface ILubanChallengeManager {
    function challengeRequests(PreconfRequest[] calldata preconfReqs) external;
}
