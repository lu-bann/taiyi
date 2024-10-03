// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import { ILubanCore } from "./interfaces/ILubanCore.sol";
import { ILubanChallengeManager } from "./interfaces/ILubanChallengeManager.sol";
import { LubanEscrow } from "./LubanEscrow.sol";
import { ProposerRegistry } from "./LubanProposerRegistry.sol";
import { PreconfRequest, TipTx, PreconfRequestStatus, PreconfTx } from "./interfaces/PreconfRequest.sol";
import { PreconfRequestLib } from "./interfaces/PreconfRequestLib.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";
import { Ownable } from "open-zeppelin/access/Ownable.sol";
import "forge-std/console.sol";
import { NonceManager } from "./NonceManager.sol";
import { SlotLib } from "./SlotLib.sol";
import { Helper } from "./Helper.sol";

contract LubanCore is Ownable, ILubanCore, LubanEscrow, ILubanChallengeManager, NonceManager {
    using PreconfRequestLib for *;
    using SignatureChecker for address;
    using Helper for bytes;
    /*//////////////////////////////////////////////////////
                          VARIABLES
    //////////////////////////////////////////////////////*/

    uint256 collectedTip;
    uint256 internal GENESIS_TIMESTAMP;
    mapping(bytes32 => uint256) public preconferTips;
    mapping(bytes32 => PreconfRequestStatus) public preconfRequestStatus;
    mapping(bytes32 => bool) public inclusionStatusMap;

    /*//////////////////////////////////////////////////////
                          EVENTS
    //////////////////////////////////////////////////////*/

    event Exhausted(address indexed preconfer, uint256 amount);
    event TipCollected(uint256 amount, bytes32 preconfRequestHash);
    event TransactionExecutionFailed(address to, uint256 value);

    constructor(address initialOwner, uint256 genesisTimestamp) Ownable(initialOwner) {
        GENESIS_TIMESTAMP = genesisTimestamp;
    }

    /*//////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////*/

    function getPreconfRequestStatus(bytes32 preconfRequestHash) external view returns (PreconfRequestStatus) {
        return preconfRequestStatus[preconfRequestHash];
    }

    function checkInclusion(bytes32 preconfRequestHash) external view returns (bool) {
        return inclusionStatusMap[preconfRequestHash];
    }

    function getCollectedTip() external view returns (uint256) {
        return collectedTip;
    }

    /*//////////////////////////////////////////////////////
                    STATE CHANGING FUNCTIONS
    //////////////////////////////////////////////////////*/

    function batchSettleRequests(PreconfRequest[] calldata preconfReqs) external payable {
        uint256 length = preconfReqs.length;
        for (uint256 i = 0; i < length;) {
            PreconfRequest calldata preconfReq = preconfReqs[i];
            this.settleRequest(preconfReq);
            unchecked {
                ++i;
            }
        }
    }

    function validateRequest(PreconfRequest calldata preconfReq) external view {
        TipTx calldata tipTx = preconfReq.tipTx;
        PreconfTx calldata preconfTx = preconfReq.preconfTx;
        bytes32 tipHash = tipTx.getTipTxHash();

        Helper.verifySignature(tipHash, tipTx.from, preconfReq.tipTxSignature);
        Helper.verifySignature(preconfTx.getPreconfTxHash(), preconfTx.from, preconfReq.preconfTx.signature);
        Helper.verifySignature(preconfReq.tipTxSignature.hashSignature(), tipTx.to, preconfReq.preconferSignature);
        Helper.verifySignature(preconfReq.getPreconfRequestHash(), this.owner(), preconfReq.preconfReqSignature);

        require(preconfTx.nonce == this.getPreconfNonce(preconfTx.from), "Incorrect preconf nonce");
        require(tipTx.nonce == this.getTipNonce(tipTx.from), "Incorrect tip nonce");
    }

    /// @notice Main bulk of the logic for validating and settling request
    /// @dev called by the preconfer to settle the request
    function settleRequest(PreconfRequest calldata preconfReq) external payable nonReentrant {
        //require(preconferList[msg.sender], "Caller is not a preconfer");

        TipTx calldata tipTx = preconfReq.tipTx;
        PreconfTx calldata preconfTx = preconfReq.preconfTx;

        uint256 slot = SlotLib.getSlotFromTimestamp(block.timestamp, GENESIS_TIMESTAMP);

        require(tipTx.target_slot == slot, "Wrong slot number");

        this.validateRequest(preconfReq);

        require(preconfReq.tipTx.to == owner(), "Tip to is not the owner");

        bool success;
        if (preconfTx.callData.length > 0) {
            // Execute contract call with provided calldata
            (success,) = payable(preconfTx.to).call{ value: preconfTx.value }(preconfTx.callData);
        } else {
            // Execute plain Ether transfer
            (success,) = payable(preconfTx.to).call{ value: preconfTx.value }("");
        }
        this.incrementPreconfNonce(preconfTx.from);

        if (!success) {
            emit TransactionExecutionFailed(preconfTx.to, preconfTx.value);
        }

        uint256 amount = payout(tipTx, true);
        handlePayment(amount, preconfReq.getPreconfRequestHash());

        this.incrementTipNonce(tipTx.from);
        preconfRequestStatus[preconfReq.getPreconfRequestHash()] = PreconfRequestStatus.Executed;
        inclusionStatusMap[preconfReq.getPreconfRequestHash()] = true;
    }

    /// @dev This function is used to exhaust the gas to the point of
    ///      `gasLimit` defined in `TipTx` iteratively, and transfer the `prePayment` to the preconfer
    ///       This mechanism is designed to prevent user "griefing" the preconfer
    ///        by allowing the preconfer to withdraw the funds that need to be exhausted
    function exhaust(PreconfRequest calldata preconfReq) external onlyOwner {
        TipTx calldata tipTx = preconfReq.tipTx;

        this.validateRequest(preconfReq);
        require(tipTx.to == owner(), "Tip to is not the owner");

        gasBurner(preconfReq.tipTx.gasLimit);

        uint256 amount = payout(tipTx, false);
        handlePayment(amount, preconfReq.getPreconfRequestHash());
        preconfRequestStatus[preconfReq.getPreconfRequestHash()] = PreconfRequestStatus.Exhausted;

        bytes32 txHash = preconfReq.getPreconfRequestHash();
        inclusionStatusMap[txHash] = true;
        emit Exhausted(msg.sender, tipTx.prePay);
    }

    function gasBurner(uint256 amount) internal {
        (bool success,) = payable(block.coinbase).call{ value: amount }("");
        require(success, "Gas burn failed");
    }

    function handlePayment(uint256 amount, bytes32 preconfRequestHash) internal {
        preconferTips[preconfRequestHash] += amount;
    }

    function collectTip(bytes32 preconfRequestHash) external {
        uint256 tipAmount = preconferTips[preconfRequestHash];
        require(tipAmount > 0, "No tip to collect");

        // Update the preconf request status to Collected
        preconfRequestStatus[preconfRequestHash] = PreconfRequestStatus.Collected;

        emit TipCollected(tipAmount, preconfRequestHash);
        collectedTip += tipAmount;
    }

    /*//////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////*/

    function challengeRequests(PreconfRequest[] calldata preconfReqs) external {
        for (uint256 i = 0; i < preconfReqs.length; i++) {
            PreconfRequest calldata preconfReq = preconfReqs[i];
            TipTx calldata tipTx = preconfReq.tipTx;

            // Verify signatures
            this.validateRequest(preconfReq);

            // Check the status of the PreconfRequest
            PreconfRequestStatus status = this.getPreconfRequestStatus(preconfReq.getPreconfRequestHash());

            require(status != PreconfRequestStatus.Collected, "PreconfRequest has already been collected");

            if (status == PreconfRequestStatus.NonInitiated) {
                uint256 slot = SlotLib.getSlotFromTimestamp(block.timestamp, GENESIS_TIMESTAMP);
                require(slot >= tipTx.target_slot, "PreconfRequest has not reached the block requested yet");
            } else if (status == PreconfRequestStatus.Executed || status == PreconfRequestStatus.Exhausted) {
                bool isIncluded = inclusionStatusMap[preconfReq.getPreconfRequestHash()];
                if (!isIncluded) {
                    // Slash the preconfer (to be implemented)
                    // eigenServiceManager.freezeOperator(tipTx.to);
                } else {
                    this.collectTip(bytes32(preconfReq.preconferSignature));
                }
            }
        }
    }
}
