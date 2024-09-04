// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface ILubanCore {
    /*//////////////////////////////////////////////////////
                          STRUCTS
    //////////////////////////////////////////////////////*/

    /// @dev Tip transaction a user sends to the preconfer
    /// gasLimit - the gas limit of the preconf transaction
    /// from - the address of the user
    /// to - the address of the preconfer
    /// prePay - is the payment a preconfer could receive after calling the exhaust function
    /// afterPay is the payment a preconfer could receive after succesffully exeucting the transaction by calling the
    /// settleRequest function
    /// nonce - prevents double spend
    struct TipTx {
        uint256 gasLimit;
        address from;
        address to;
        uint256 prePay;
        uint256 afterPay;
        uint256 nonce;
    }

    struct PreconfTx {
        address to;
        uint256 value;
        bytes callData;
        bool ethTransfer;
    }

    struct OrderingMeta {
        uint256 txCount;
        uint256 index; // if 0, then no ordering is required
    }

    struct InclusionMeta {
        uint256 startingBlockNumber;
    }

    struct PreconfConditions {
        InclusionMeta inclusionMetaData;
        OrderingMeta orderingMetaData;
        uint256 blockNumber;
    }

    struct PreconfRequest {
        TipTx tipTx;
        PreconfConditions prefConditions;
        PreconfTx preconfTx;
        bytes tipTxSignature;
        bytes initSignature;
        bytes preconferSignature;
        bytes preconfTxSignature;
    }

    enum PreconfRequestStatus {
        NonInitiated, // default value
        Exhausted,
        Executed,
        Collected
    }

    /*//////////////////////////////////////////////////////
                          FUNCTIONS
    //////////////////////////////////////////////////////*/

    function settleRequest(PreconfRequest calldata preconfReq) external payable returns (bytes32);

    function checkInclusion(address from, uint256 blockNumber, bytes32 txHash) external view returns (bool);

    function exhaust(
        TipTx calldata tipTx,
        PreconfConditions calldata preconfConditions,
        bytes calldata userSignature,
        bytes calldata preconferSignature
    )
        external;

    function getTipTxHash(ILubanCore.TipTx calldata tipTx) external view returns (bytes32);

    function handlePayment(uint256 amount, address preconferAddr, bytes calldata preconferSig) external payable;

    function getTipTxAndPreconfConditionsHash(
        TipTx calldata tipTx,
        PreconfConditions calldata preconfConditions
    )
        external
        view
        returns (bytes32);

    function getPreconfRequestStatus(bytes32 preconferSignature) external view returns (PreconfRequestStatus);

    function collectTip(address preconfer, bytes32 preconferSignature) external;
}
