// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import { ITaiyiCore } from "./interfaces/ITaiyiCore.sol";
import { ITaiyiChallengeManager } from "./interfaces/ITaiyiChallengeManager.sol";
import { TaiyiEscrow } from "./TaiyiEscrow.sol";
import { TaiyiProposerRegistry } from "./TaiyiProposerRegistry.sol";
import { TaiyiDelegation } from "./TaiyiDelegation.sol";
import { PreconfRequest, TipTx, PreconfRequestStatus, PreconfTx } from "./interfaces/Types.sol";
import { PreconfRequestLib } from "./libs/PreconfRequestLib.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";
import { Ownable } from "open-zeppelin/access/Ownable.sol";
import "forge-std/console.sol";
import { NonceManager } from "./utils/NonceManager.sol";
import { SlotLib } from "./libs/SlotLib.sol";
import { Helper } from "./utils/Helper.sol";

contract TaiyiCore {
    struct InclusionTx {
        address from;
        address to;
        uint256 value;
        bytes callData;
    }

    function batchSettleRequestsV2(InclusionTx[] calldata inclusionReqs) external payable {
        for (uint256 i = 0; i < inclusionReqs.length; i++) {
            InclusionTx memory inclusionReq = inclusionReqs[i];
            bool success;
            if (inclusionReq.callData.length > 0) {
                // Execute contract call with provided calldata
                (success,) = payable(inclusionReq.to).call{ value: inclusionReq.value }(inclusionReq.callData);
            } else {
                // Execute plain Ether transfer
                (success,) = payable(inclusionReq.to).call{ value: inclusionReq.value }("");
            }
            if (!success) {
                revert("TaiyiCore: batchSettleRequestsV2: call failed");
            }
        }
    }
}
