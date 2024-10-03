// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequest, PreconfRequestStatus } from "./PreconfRequest.sol";

interface ILubanCore {
    /*//////////////////////////////////////////////////////
                          STRUCTS
    //////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////
                          FUNCTIONS
    //////////////////////////////////////////////////////*/

    function settleRequest(PreconfRequest calldata preconfReq) external payable;

    function checkInclusion(bytes32 preconfRequestHash) external view returns (bool);

    function exhaust(PreconfRequest calldata preconfReq) external;

    function getPreconfRequestStatus(bytes32 preconferSignature) external view returns (PreconfRequestStatus);

    function collectTip(bytes32 preconferSignature) external;
}
