// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ILubanCore } from "./interfaces/ILubanCore.sol";
import { ILubanChallengeManager } from "./interfaces/ILubanChallengeManager.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";

contract LubanChallengeManager is ILubanChallengeManager {
    ILubanCore public lubanCore;

    constructor(address _lubanCore) {
        lubanCore = ILubanCore(_lubanCore);
    }

    function challengeRequests(ILubanCore.PreconfRequest[] calldata preconfReqs) external {
        for (uint256 i = 0; i < preconfReqs.length; i++) {
            ILubanCore.PreconfRequest calldata preconfReq = preconfReqs[i];
            ILubanCore.TipTx calldata tipTx = preconfReq.tipTx;
            ILubanCore.PreconfConditions calldata preconfConditions = preconfReq.prefConditions;

            // Verify signatures
            bytes32 txHash = lubanCore.getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);
            require(ECDSA.recover(txHash, preconfReq.initSignature) == tipTx.from, "Invalid user signature");
            require(
                ECDSA.recover(bytes32(preconfReq.initSignature), preconfReq.preconferSignature) == tipTx.to,
                "Invalid preconfer signature"
            );

            // Check the status of the PreconfRequest
            ILubanCore.PreconfRequestStatus status =
                lubanCore.getPreconfRequestStatus(bytes32(preconfReq.preconferSignature));

            require(status != ILubanCore.PreconfRequestStatus.Collected, "PreconfRequest has already been collected");

            if (status == ILubanCore.PreconfRequestStatus.NonInitiated) {
                require(
                    block.number >= preconfConditions.blockNumber,
                    "PreconfRequest has not reached the block requested yet"
                );

            } else if (status == ILubanCore.PreconfRequestStatus.Executed || status == ILubanCore.PreconfRequestStatus.Exhausted) {
                bool isIncluded = lubanCore.checkInclusion(tipTx.from, preconfConditions.blockNumber, txHash);
                if (!isIncluded) {
                    // Slash the preconfer (to be implemented)
                    // eigenServiceManager.freezeOperator(tipTx.to);
                } else {
                    lubanCore.collectTip(tipTx.to, bytes32(preconfReq.preconferSignature));
                }
            }
        }
    }
}
