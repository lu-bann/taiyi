// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PreconfRequestStatus } from "../types/CommonTypes.sol";
import { PreconfRequestBType } from "../types/PreconfRequestBTypes.sol";

interface ITaiyiCore {
    function checkInclusion(bytes32 preconfRequestHash) external view returns (bool);
    function exhaust(PreconfRequestBType calldata preconfReq) external;
    function getPreconfRequestStatus(bytes32 preconferSignature)
        external
        view
        returns (PreconfRequestStatus);
    function collectTip(bytes32 preconferSignature) external;
}
