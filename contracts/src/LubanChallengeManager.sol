// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { AxiomV2Client } from "@axiom-crypto/v2-periphery/client/AxiomV2Client.sol";
import { IAxiomV2Query } from "@axiom-crypto/v2-periphery/interfaces/query/IAxiomV2Query.sol";
import { ILubanCore } from "./interfaces/ILubanCore.sol";
import { ILubanChallengeManager } from "./interfaces/ILubanChallengeManager.sol";
import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";

contract LubanChallengeManager is AxiomV2Client, ILubanChallengeManager {
    /// @dev The unique identifier of the circuit accepted by this contract.
    bytes32 immutable QUERY_SCHEMA;

    /// @dev The chain ID of the chain whose data the callback is expected to be called from.
    uint64 immutable SOURCE_CHAIN_ID;

    ILubanCore public lubanCore;

    using SignatureChecker for address;

    /// @notice Construct a new LubanChallengeManager contract.
    /// @param  axiomV2QueryAddress_ The address of the AxiomV2Query contract.
    /// @param  callbackSourceChainId_ The ID of the chain the query reads from.
    constructor(
        address axiomV2QueryAddress_,
        uint64 callbackSourceChainId_,
        bytes32 querySchema_,
        address _lubanCore
    )
        AxiomV2Client(axiomV2QueryAddress_)
    {
        QUERY_SCHEMA = querySchema_;
        SOURCE_CHAIN_ID = callbackSourceChainId_;
        lubanCore = ILubanCore(_lubanCore);
    }

    /// @inheritdoc AxiomV2Client
    function _validateAxiomV2Call(
        AxiomCallbackType, // callbackType,
        uint64 sourceChainId,
        address, // caller,
        bytes32 querySchema,
        uint256, // queryId,
        bytes calldata // extraData
    )
        internal
        view
        override
    {
        require(sourceChainId == SOURCE_CHAIN_ID, "Source chain ID does not match");
        require(querySchema == QUERY_SCHEMA, "Invalid query schema");
    }

    /// @inheritdoc AxiomV2Client
    function _axiomV2Callback(
        uint64, // sourceChainId,
        address caller, // caller,
        bytes32, // querySchema,
        uint256, // queryId,
        bytes32[] calldata axiomResults,
        bytes calldata // extraData
    )
        internal
        override
    {
        // TipTx
        ILubanCore.TipTx memory tipTx = ILubanCore.TipTx(
            uint256(axiomResults[0]),
            address(uint160(uint256(axiomResults[1]))),
            address(uint160(uint256(axiomResults[2]))),
            uint256(axiomResults[3]),
            uint256(axiomResults[4]),
            uint256(axiomResults[5])
        );

        // PreconfConditions
        ILubanCore.InclusionMeta memory inclusionMetaData = ILubanCore.InclusionMeta(uint256(axiomResults[6]));
        ILubanCore.OrderingMeta memory orderingMetaData =
            ILubanCore.OrderingMeta(uint256(axiomResults[7]), uint256(axiomResults[8]));
        ILubanCore.PreconfConditions memory preconfConditions =
            ILubanCore.PreconfConditions(inclusionMetaData, orderingMetaData, uint256(axiomResults[9]));

        // User signature over TipTx and PreconfConditions
        bytes memory userSig = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            userSig[i] = axiomResults[14][i];
        }

        // Preconfers signature over user signature
        bytes memory preconferSig = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            preconferSig[i] = axiomResults[15][i];
        }

        // Signature verification over PreconfRequest
        bytes32 txHash = lubanCore.getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);
        require(ECDSA.recover(txHash, userSig) == tipTx.from, "Invalid user signature");
        require(ECDSA.recover(bytes32(userSig), preconferSig) == tipTx.to, "Invalid preconfer signature");

        // Check the status of the PreconfRequest
        ILubanCore.PreconfRequestStatus status = lubanCore.getPreconfRequestStatus(bytes32(preconferSig));

        require(status != ILubanCore.PreconfRequestStatus.Collected, "PreconfRequest has already been collected");
        if (status == ILubanCore.PreconfRequestStatus.NonInitiated) {
            require(
                block.number >= preconfConditions.blockNumber, "PreconfRequest has not reached the block requested yet"
            );

            // This means the preconfer neither called the settleRequest nor exhaust at or before the blockNumber
            // specified in the preconfConditions, which is a violation of the protocol. Hence, the preconfer should be
            // slashed.
            //
            // Note: the slashing mechanism is yet to be implemented for Eigenlayer. Thus, calling freezeOperator don't
            // have any effect.
            // eigenServiceManager.freezeOperator(tipTx.To);
        } else if (status == ILubanCore.PreconfRequestStatus.Exhausted) {
            lubanCore.collectTip(tipTx.to, bytes32(preconferSig));
        } else if (status == ILubanCore.PreconfRequestStatus.Executed) {
            if (orderingMetaData.index == 0) {
                // if 0, then no ordering is required
                lubanCore.collectTip(tipTx.to, bytes32(preconferSig));
            } else {
                // only checking to address and function selector for simplicity for now
                // More sophisticated checks can be added in the future
                address toAddrFromCallback = address(uint160(uint256(axiomResults[16])));
                bytes32 functionSelector = axiomResults[17];
                if (toAddrFromCallback == address(lubanCore) && functionSelector == lubanCore.settleRequest.selector) {
                    lubanCore.collectTip(tipTx.to, bytes32(preconferSig));
                } else {
                    // eigenServiceManager.freezeOperator(tipTx.To);
                }
            }
        }
    }
}
