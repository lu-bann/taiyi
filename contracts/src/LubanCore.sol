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
    mapping(address => mapping(uint256 => mapping(bytes32 => bool))) public inclusionStatusMap;


    /*//////////////////////////////////////////////////////
                          EVENTS
    //////////////////////////////////////////////////////*/

    event Exhausted(address indexed preconfer, uint256 amount);
    event TipCollected(address indexed preconfer, uint256 amount, bytes32 preconferSignature);
    event TransactionExecutionFailed(address to, uint256 value);

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
        lubanChallengeManager = new LubanChallengeManager(address(this));
    }

    /*//////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////*/

    function getPreconfRequestStatus(bytes32 preconferSignature) external view returns (PreconfRequestStatus) {
        return preconfRequestStatus[preconferSignature];
    }

    function isPreconfer(address _address) public view returns (bool) {
        return preconferList[_address];
    }

    function getLubanEscrow() external view returns (LubanEscrow) {
        return lubanEscrow;
    }

    function getPreconferBalance(address preconfer, bytes calldata preconferSig) external view returns (uint256) {
        return preconferTips[preconfer][bytes32(preconferSig)];
    }

    function checkInclusion(address preconfer, uint256 blockNumber, bytes32 txHash) external view returns (bool) {
        return inclusionStatusMap[preconfer][blockNumber][txHash];
    }

    /*//////////////////////////////////////////////////////
                    STATE CHANGING FUNCTIONS
    //////////////////////////////////////////////////////*/

    function batchSettleRequests(PreconfRequest[] calldata preconfReqs) external payable {
        require(preconferList[msg.sender], "Caller is not a preconfer");
        uint256 length = preconfReqs.length;
        for (uint256 i = 0; i < length;) {
            PreconfRequest calldata preconfReq = preconfReqs[i];
            bytes32 txHash = this.settleRequest(preconfReq);
            inclusionStatusMap[msg.sender][block.number][txHash] = true;
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Main bulk of the logic for validating and settling request
    /// @dev called by the preconfer to settle the request
    function settleRequest(PreconfRequest calldata preconfReq) external payable returns (bytes32) {
        //require(preconferList[msg.sender], "Caller is not a preconfer");

        TipTx calldata tipTx = preconfReq.tipTx;
        PreconfTx calldata preconfTx = preconfReq.preconfTx;
        PreconfConditions calldata preconfConditions = preconfReq.prefConditions;

        require(preconfConditions.blockNumber == block.number, "Wrong block number");

        // Validate the signature of the tipTx + preconfConditions
        bytes32 txHash = getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);

        address signer = verifySignature(txHash, preconfReq.initSignature);
        require(signer == tipTx.from, "Invalid user signature");

        signer = verifySignature(bytes32(preconfReq.initSignature), preconfReq.preconferSignature);
        require(signer == tipTx.to, "Invalid preconfer signature");

        signer = verifySignature(getPreconfTxHash(preconfTx), preconfReq.preconfTxSignature);
        require(signer == tipTx.from, "Invalid preconf tx signature");

        bool success;
        if (!preconfTx.ethTransfer) {
            // Execute contract call with provided calldata
            require(preconfTx.callData.length > 0, "Calldata is empty");
            (success,) = payable(preconfTx.to).call{ value: preconfTx.value }(preconfTx.callData);
        } else {
            // Execute plain Ether transfer
            (success,) = payable(preconfTx.to).call{ value: preconfTx.value }("");
        }

        if (!success) {
            emit TransactionExecutionFailed(preconfTx.to, preconfTx.value);
        }

        lubanEscrow.payout(tipTx, preconfReq.tipTxSignature, true, preconfReq.preconferSignature);
        preconfRequestStatus[bytes32(preconfReq.preconferSignature)] = PreconfRequestStatus.Executed;
        return txHash;
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
    function exhaust(
        TipTx calldata tipTx,
        PreconfConditions calldata preconfConditions,
        bytes calldata userSignature,
        bytes calldata preconferSignature
    )
        external
    {
        require(preconferList[msg.sender], "Caller is not a preconfer");

        bytes32 txHash = getTipTxHash(tipTx);
        require(verifySignature(txHash, userSignature) == tipTx.from, "Invalid signature");

        unchecked {
            gasBurner(tipTx.gasLimit);
        }

        lubanEscrow.payout(tipTx, userSignature, false, preconferSignature);
        preconfRequestStatus[bytes32(preconferSignature)] = PreconfRequestStatus.Exhausted;

        txHash = getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);
        inclusionStatusMap[msg.sender][preconfConditions.blockNumber][txHash] = true;
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
        uint256 gasCost;
        assembly {
            for { } lt(gasCost, gasLimit) { } {
                // Check if we're about to exceed gasLimit
                if gt(add(gasCost, sub(startGas, gas())), gasLimit) { break }
                gasCost := add(gasCost, sub(startGas, gas()))
                startGas := gas()
            }
        }

        return gasCost;
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

    function getPreconfTxHash(PreconfTx calldata preconfTx) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _getPreconfTxHash(preconfTx)));
    }

    function _getPreconfTxHash(PreconfTx calldata preconfTx) internal pure returns (bytes32) {
        return keccak256(abi.encode(preconfTx.to, preconfTx.value, preconfTx.callData, preconfTx.ethTransfer));
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
