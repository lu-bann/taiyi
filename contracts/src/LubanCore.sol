// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import { ILubanCore } from "./interfaces/ILubanCore.sol";
import { ILubanChallengeManager } from "./interfaces/ILubanChallengeManager.sol";
import { LubanEscrow } from "./LubanEscrow.sol";
import { ProposerRegistry } from "./LubanProposerRegistry.sol";
import { PreconfRequest, TipTx, PreconfRequestStatus, PreconfTx } from "./interfaces/Types.sol";
import { PreconfRequestLib } from "./libs/PreconfRequestLib.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";
import { Ownable } from "open-zeppelin/access/Ownable.sol";
import "forge-std/console.sol";
import { NonceManager } from "./utils/NonceManager.sol";
import { SlotLib } from "./libs/SlotLib.sol";
import { Helper } from "./utils/Helper.sol";

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

    /**
     * @notice Returns the status of a given PreconfRequest.
     * @dev This function retrieves the status of a PreconfRequest using its hash.
     * @param preconfRequestHash The hash of the PreconfRequest.
     * @return The status of the PreconfRequest.
     */
    function getPreconfRequestStatus(bytes32 preconfRequestHash) public view returns (PreconfRequestStatus) {
        return preconfRequestStatus[preconfRequestHash];
    }

    /**
     * @notice Checks if a given PreconfRequest is included.
     * @dev This function checks the inclusion status of a PreconfRequest using its hash.
     * @param preconfRequestHash The hash of the PreconfRequest.
     * @return True if the PreconfRequest is included, false otherwise.
     */
    function checkInclusion(bytes32 preconfRequestHash) external view returns (bool) {
        return inclusionStatusMap[preconfRequestHash];
    }

    /**
     * @notice Returns the collected tip amount.
     * @dev This function retrieves the total amount of collected tips.
     * @return The collected tip amount.
     */
    function getCollectedTip() external view returns (uint256) {
        return collectedTip;
    }

    /*//////////////////////////////////////////////////////
                    STATE CHANGING FUNCTIONS
    //////////////////////////////////////////////////////*/

    /**
     * @notice Batches settles multiple PreconfRequests.
     * @dev This function processes a list of PreconfRequests in a single call.
     * @param preconfReqs An array of PreconfRequest structs to be settled.
     */
    function batchSettleRequests(PreconfRequest[] calldata preconfReqs) external payable {
        uint256 length = preconfReqs.length;
        for (uint256 i = 0; i < length;) {
            PreconfRequest calldata preconfReq = preconfReqs[i];
            settleRequest(preconfReq);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Validates the given PreconfRequest.
     * @dev This function checks the signatures and nonces of the provided PreconfRequest.
     * @param preconfReq The PreconfRequest to validate.
     */
    function validateRequest(PreconfRequest calldata preconfReq) public view {
        TipTx calldata tipTx = preconfReq.tipTx;
        PreconfTx calldata preconfTx = preconfReq.preconfTx;
        bytes32 tipHash = tipTx.getTipTxHash();

        Helper.verifySignature(tipHash, tipTx.from, preconfReq.tipTxSignature);
        Helper.verifySignature(preconfTx.getPreconfTxHash(), preconfTx.from, preconfReq.preconfTx.signature);
        Helper.verifySignature(preconfReq.tipTxSignature.hashSignature(), tipTx.to, preconfReq.preconferSignature);
        Helper.verifySignature(preconfReq.getPreconfRequestHash(), tipTx.to, preconfReq.preconfReqSignature);

        require(preconfTx.nonce == getPreconfNonce(preconfTx.from), "Incorrect preconf nonce");
        require(tipTx.nonce == getTipNonce(tipTx.from), "Incorrect tip nonce");
    }

    /// @notice Main bulk of the logic for validating and settling request
    /// @dev called by the preconfer to settle the request
    function settleRequest(PreconfRequest calldata preconfReq) public payable nonReentrant {
        //require(preconferList[msg.sender], "Caller is not a preconfer");

        TipTx calldata tipTx = preconfReq.tipTx;
        PreconfTx calldata preconfTx = preconfReq.preconfTx;

        uint256 slot = SlotLib.getSlotFromTimestamp(block.timestamp, GENESIS_TIMESTAMP);

        require(tipTx.target_slot == slot, "Wrong slot number");

        validateRequest(preconfReq);

        require(preconfReq.tipTx.to == owner(), "Tip to is not the owner");

        bool success;
        if (preconfTx.callData.length > 0) {
            // Execute contract call with provided calldata
            (success,) = payable(preconfTx.to).call{ value: preconfTx.value }(preconfTx.callData);
        } else {
            // Execute plain Ether transfer
            (success,) = payable(preconfTx.to).call{ value: preconfTx.value }("");
        }
        incrementPreconfNonce(preconfTx.from);

        if (!success) {
            emit TransactionExecutionFailed(preconfTx.to, preconfTx.value);
        }

        uint256 amount = payout(tipTx, true);
        handlePayment(amount, preconfReq.getPreconfRequestHash());

        incrementTipNonce(tipTx.from);
        preconfRequestStatus[preconfReq.getPreconfRequestHash()] = PreconfRequestStatus.Executed;
        inclusionStatusMap[preconfReq.getPreconfRequestHash()] = true;
    }

    /// @dev This function is used to exhaust the gas to the point of
    ///      `gasLimit` defined in `TipTx` iteratively, and transfer the `prePayment` to the preconfer
    ///       This mechanism is designed to prevent user "griefing" the preconfer
    ///        by allowing the preconfer to withdraw the funds that need to be exhausted
    function exhaust(PreconfRequest calldata preconfReq) external onlyOwner {
        TipTx calldata tipTx = preconfReq.tipTx;

        validateRequest(preconfReq);
        require(tipTx.to == owner(), "Tip to is not the owner");

        gasBurner(preconfReq.tipTx.gasLimit);

        uint256 amount = payout(tipTx, false);
        handlePayment(amount, preconfReq.getPreconfRequestHash());
        preconfRequestStatus[preconfReq.getPreconfRequestHash()] = PreconfRequestStatus.Exhausted;

        bytes32 txHash = preconfReq.getPreconfRequestHash();
        inclusionStatusMap[txHash] = true;
        emit Exhausted(msg.sender, tipTx.prePay);
    }

    /**
     * @notice Burns gas by transferring the specified amount to the coinbase.
     * @dev This function attempts to transfer the given amount of gas to the block's coinbase.
     * @param amount The amount of gas to be burned.
     */
    function gasBurner(uint256 amount) internal {
        (bool success,) = payable(block.coinbase).call{ value: amount }("");
        require(success, "Gas burn failed");
    }

    /**
     * @notice Handles the payment by updating the preconfer tips.
     * @dev This function adds the specified amount to the preconfer tips.
     * @param amount The amount to be added to the preconfer tips.
     * @param preconfRequestHash The hash of the PreconfRequest.
     */
    function handlePayment(uint256 amount, bytes32 preconfRequestHash) internal {
        preconferTips[preconfRequestHash] += amount;
    }

    /**
     * @notice Collects the tip for a given PreconfRequest.
     * @dev This function collects the tip amount for a PreconfRequest and updates the status.
     * @param preconfRequestHash The hash of the PreconfRequest.
     */
    function collectTip(bytes32 preconfRequestHash) public {
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

    /**
     * @notice Challenges multiple PreconfRequests.
     * @dev This function processes a list of PreconfRequests in a single call.
     * @param preconfReqs An array of PreconfRequest structs to be challenged.
     */
    function challengeRequests(PreconfRequest[] calldata preconfReqs) external {
        for (uint256 i = 0; i < preconfReqs.length; i++) {
            PreconfRequest calldata preconfReq = preconfReqs[i];
            TipTx calldata tipTx = preconfReq.tipTx;

            // Verify signatures
            validateRequest(preconfReq);

            // Check the status of the PreconfRequest
            PreconfRequestStatus status = getPreconfRequestStatus(preconfReq.getPreconfRequestHash());

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
                    collectTip(bytes32(preconfReq.preconferSignature));
                }
            }
        }
    }
}
