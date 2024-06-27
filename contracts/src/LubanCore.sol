// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { SignatureChecker } from "open-zeppelin/utils/cryptography/SignatureChecker.sol";
import { ILubanCore } from "./interfaces/ILubanCore.sol";
import { LubanEscrow } from "./LubanEscrow.sol";
import { LubanChallengeManager } from "./LubanChallengeManager.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";
import "forge-std/console.sol";

contract LubanCore is ILubanCore {
    /*//////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////*/

    bytes32 constant TIP_TX_TYPEHASH =
        keccak256("TipTx(uint256 gasLimit,address from,address to,uint256 prePay,uint256 afterPay)");

    bytes32 constant INCLUSION_META_TYPEHASH = keccak256("InclusionMeta(uint256 startingBlockNumber)");

    bytes32 constant ORDERING_META_TYPEHASH = keccak256("OrderingMeta(uint256 txCount,uint256 index)");

    bytes32 constant PRECONF_CONDITIONS_TYPEHASH = keccak256(
        abi.encodePacked(
            "PreconfConditions(",
            "InclusionMeta inclusionMetaData,",
            "OrderingMeta orderingMetaData,",
            "uint256 blockNumber",
            ")"
        )
    );

    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /*//////////////////////////////////////////////////////
                          VARIABLES
    //////////////////////////////////////////////////////*/

    using SignatureChecker for address;

    LubanEscrow public lubanEscrow;
    LubanChallengeManager public lubanChallengeManager;

    address public owner;
    bytes32 public DOMAIN_SEPARATOR;

    mapping(address => bool) public preconferList;
    mapping(address => mapping(bytes32 => uint256)) public preconferTips;
    mapping(bytes32 => PreconfRequestStatus) public preconfRequestStatus;

    /*//////////////////////////////////////////////////////
                          EVENTS
    //////////////////////////////////////////////////////*/

    event Exhausted(address indexed preconfer, uint256 amount);
    event TipCollected(address indexed preconfer, uint256 amount, bytes32 preconferSignature);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    modifier onlyChallengeManager() {
        require(msg.sender == address(lubanChallengeManager), "Only LubanChallengeManager can call this function");
        _;
    }

    constructor(address _owner, address _axiomV2QueryAddress, bytes32 _querySchema) {
        owner = _owner;

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                // Contract name
                keccak256(bytes("LubanCore")),
                // Version
                keccak256(bytes("1.0")),
                // Chain ID
                chainId
            )
        );

        lubanEscrow = new LubanEscrow(address(this));
        lubanChallengeManager =
            new LubanChallengeManager(_axiomV2QueryAddress, uint64(chainId), _querySchema, address(this));
    }

    /*//////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////*/

    function getPreconfRequestStatus(bytes32 preconferSignature) external view returns (PreconfRequestStatus) {
        return preconfRequestStatus[preconferSignature];
    }

    function getLubanEscrow() external view returns (LubanEscrow) {
        return lubanEscrow;
    }

    function getPreconferBalance(address preconfer, bytes calldata preconferSig) external view returns (uint256) {
        return preconferTips[preconfer][bytes32(preconferSig)];
    }

    /*//////////////////////////////////////////////////////
                    STATE CHANGING FUNCTIONS
    //////////////////////////////////////////////////////*/

    /// @notice Main bulk of the logic for validating and settling request
    /// @dev called by the preconfer to settle the request
    function settleRequest(PreconfRequest calldata preconfReq) external payable {
        require(preconferList[msg.sender], "Caller is not a preconfer");

        TipTx calldata tipTx = preconfReq.tipTx;
        PreconfTx calldata preconfTx = preconfReq.preconfTx;
        PreconfConditions calldata preconfConditions = preconfReq.prefConditions;

        require(preconfConditions.blockNumber == block.number, "Preconf request submitted at the wrong block number");

        // Validate the signature of the tipTx + preconfConditions
        bytes32 txHash = getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);
        require(verifySignature(txHash, preconfReq.initSignature) == tipTx.from, "Invalid user signature");
        require(
            verifySignature(bytes32(preconfReq.initSignature), preconfReq.preconferSignature) == tipTx.to,
            "Invalid preconfer signature"
        );

        if (!preconfTx.ethTransfer) {
            // Execute contract call with provided calldata
            require(preconfTx.callData.length > 0, "Calldata is empty");
            (bool _status,) = payable(preconfTx.to).call{ value: preconfTx.value }(preconfTx.callData);
        } else {
            // Execute plain Ether transfer
            (bool _status,) = payable(preconfTx.to).call{ value: preconfTx.value }("");
        }

        lubanEscrow.payout(tipTx, preconfReq.tipTxSignature, true, preconfReq.preconferSignature);

        preconfRequestStatus[bytes32(preconfReq.preconferSignature)] = PreconfRequestStatus.Executed;
    }

    /// @dev This function is used to exhaust the gas to the point of
    ///      `gasLimit` defined in `TipTx` iteratively, and transfer the `prePayment` to the preconfer
    ///       This mechanism is designed to prevent user "griefing" the preconfer
    ///       by allowing the preconfer to withdraw the `prePayment` if
    ///       the user either withholds the `PreconfTx`
    ///       or submit a `PreconfTx` that exceeds the `gasLimit`
    /// @notice only the preconfer could invoke this function
    /// @param tipTx The TipTx struct
    /// @param userSignature The signature of the TipTx
    function exhaust(TipTx calldata tipTx, bytes calldata userSignature, bytes calldata preconferSignature) external {
        require(preconferList[msg.sender], "Caller is not a preconfer");

        bytes32 txHash = getTipTxHash(tipTx);
        require(verifySignature(txHash, userSignature) == tipTx.from, "Invalid signature");

        gasBurner(tipTx.gasLimit);
        lubanEscrow.payout(tipTx, userSignature, false, preconferSignature);
        preconfRequestStatus[bytes32(preconferSignature)] = PreconfRequestStatus.Exhausted;
        emit Exhausted(msg.sender, tipTx.prePay);
    }

    function registerPreconfer(address preconfer) external onlyOwner {
        preconferList[preconfer] = true;
    }

    function handlePayment(uint256 amount, address preconferAddr, bytes calldata preconferSig) external payable {
        require(msg.sender == address(lubanEscrow), "Only LubanEscrow can call this function");
        require(msg.value == amount, "Mismatched ether sent");
        preconferTips[preconferAddr][bytes32(preconferSig)] += amount;
    }

    function collectTip(address preconfer, bytes32 preconferSignature) external onlyChallengeManager {
        uint256 tipAmount = preconferTips[preconfer][preconferSignature];
        require(tipAmount > 0, "No tip to collect");

        (bool sent,) = preconfer.call{ value: tipAmount }("");
        require(sent, "Failed to send Ether");

        // Update the preconf request status to Collected
        preconfRequestStatus[preconferSignature] = PreconfRequestStatus.Collected;

        emit TipCollected(preconfer, tipAmount, preconferSignature);
        preconferTips[preconfer][preconferSignature] = 0;
    }

    /// @dev Fallback function to receive Ether from LubanEscrow's payout()
    receive() external payable { }

    /*//////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////*/

    function gasBurner(uint256 gasLimit) public view returns (uint256) {
        uint256 startGas = gasleft();
        uint256 gasCost = 0;
        while (gasCost < gasLimit) {
            // to prevent adding extra gas over the gasLimit
            if ((gasCost + startGas - gasleft()) > gasLimit) {
                break;
            } else {
                gasCost += startGas - gasleft();
            }
            startGas = gasleft();
        }
        return gasCost;
    }

    function getPreconfRequestHash(PreconfRequest calldata preconfReq) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                preconfReq.tipTx,
                preconfReq.prefConditions,
                preconfReq.preconfTx,
                preconfReq.tipTxSignature,
                preconfReq.initSignature,
                preconfReq.preconferSignature
            )
        );
    }

    function getTipTxAndPreconfConditionsHash(
        TipTx calldata tipTx,
        PreconfConditions calldata preconfConditions
    )
        public
        view
        override
        returns (bytes32)
    {
        bytes32 tipTxHash = getTipTxHash(tipTx);
        bytes32 preconfConditionsHash = getPreconfConditionsHash(preconfConditions);
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, tipTxHash, preconfConditionsHash));
    }

    function getTipTxHash(TipTx calldata tipTx) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _getTipTxHash(tipTx)));
    }

    function _getTipTxHash(TipTx calldata tipTx) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(TIP_TX_TYPEHASH, tipTx.gasLimit, tipTx.from, tipTx.to, tipTx.prePay, tipTx.afterPay, tipTx.nonce)
        );
    }

    function getPreconfConditionsHash(PreconfConditions calldata preconfConditions) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _getPreconfConditionsHash(preconfConditions)));
    }

    function _getPreconfConditionsHash(PreconfConditions calldata preconfConditions) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PRECONF_CONDITIONS_TYPEHASH,
                preconfConditions.inclusionMetaData.startingBlockNumber,
                preconfConditions.orderingMetaData.txCount,
                preconfConditions.orderingMetaData.index,
                preconfConditions.blockNumber
            )
        );
    }

    /// @dev Checks if the signature is valid for 712-signed data
    /// @param _hash The hash of the data
    /// @param _signature The signature
    /// @return True if the signature is valid
    function verifySignature(bytes32 _hash, bytes calldata _signature) internal pure returns (address) {
        return ECDSA.recover(_hash, _signature);
    }
}
