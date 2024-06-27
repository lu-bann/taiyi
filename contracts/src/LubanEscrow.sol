// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/console.sol";

import "./interfaces/ILubanCore.sol";
import "./LubanCore.sol";
import "open-zeppelin/utils/ReentrancyGuard.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";
import "open-zeppelin/utils/cryptography/MessageHashUtils.sol";

contract LubanEscrow is ReentrancyGuard {
    using ECDSA for bytes32;

    ILubanCore public lubanCore;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockBlock;
    mapping(address => uint256) public nonce;

    address public lubanCoreAddr;
    uint256 public constant LOCK_PERIOD = 64;
    uint256 public maxUint256 = type(uint256).max;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event PaymentMade(address indexed from, uint256 amount, bool isAfterExec);
    event RequestedWithdraw(address indexed user, uint256 amount);

    constructor(address _lubanCore) {
        require(_lubanCore != address(0), "LubanCore address cannot be zero");
        lubanCoreAddr = _lubanCore;
        lubanCore = ILubanCore(_lubanCore);
    }

    receive() external payable {
        deposit();
    }

    /// @dev Returns the lock block of a user
    /// @param user The user address
    /// @return The lock block of the user
    function lockBlockOf(address user) public view returns (uint256) {
        return lockBlock[user];
    }

    /// @dev Returns the balance of a user
    /// @param user The user address
    /// @return The balance of the user
    function balanceOf(address user) public view returns (uint256) {
        return balances[user];
    }

    /// @dev Deposits Ether into the
    /// @notice The lockBlock is set to maxUint256
    function deposit() public payable {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        balances[msg.sender] += msg.value;
        lockBlock[msg.sender] = maxUint256;
        emit Deposited(msg.sender, msg.value);
    }

    /// @dev to withdraw a user needs to call requestWithdraw first
    ///      to record the block number at which the withdrawal was requested
    /// @notice calling deposit after requestWithdra will reset the lockBlock to maxUint256
    /// @param amount The amount to withdraw
    function requestWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance to request withdraw");
        lockBlock[msg.sender] = block.number;
        emit RequestedWithdraw(msg.sender, amount);
    }

    /// @dev Withdraws the amount requested by the user
    /// @notice The lockBlock is reset to maxUint256 after withdrawal
    /// @param amount The amount to withdrawal
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(
            lockBlock[msg.sender] != maxUint256 && block.number >= lockBlock[msg.sender] + LOCK_PERIOD,
            "Withdrawal is locked"
        );
        balances[msg.sender] -= amount;
        (bool sent,) = payable(msg.sender).call{ value: amount }("");
        require(sent, "Failed to send Ether");
        lockBlock[msg.sender] = maxUint256;
        emit Withdrawn(msg.sender, amount);
    }

    /// @dev Payout to the preconfer after the PreconfRequest is executed
    ///      Can only be called by LubanCore
    /// @param tipTx The TipTx struct
    /// @param signature The signature of the TipTx
    /// @param isAfterExec Whether the payout is after the execution of the PreconfRequest
    function payout(
        ILubanCore.TipTx calldata tipTx,
        bytes calldata signature,
        bool isAfterExec,
        bytes calldata preconfSig
    )
        public
        nonReentrant
    {
        require(msg.sender == lubanCoreAddr, "Only LubanCore can initiate this payout");
        bytes32 txHash = lubanCore.getTipTxHash(tipTx);
        require(verifySignature(txHash, signature) == tipTx.from, "Invalid signature");

        uint256 amount = isAfterExec ? tipTx.prePay + tipTx.afterPay : tipTx.prePay;
        require(balances[tipTx.from] >= amount, "Insufficient balance");

        require(tipTx.nonce == nonce[tipTx.from], "Incorrect tip nonce");
        nonce[tipTx.from]++;

        balances[tipTx.from] -= amount;
        lubanCore.handlePayment{ value: amount }(amount, tipTx.to, preconfSig);
        emit PaymentMade(tipTx.from, amount, isAfterExec);
    }

    /// @dev Checks if the signature is valid for 712-signed data
    /// @param _hash The hash of the data
    /// @param _signature The signature
    /// @return True if the signature is valid
    function verifySignature(bytes32 _hash, bytes calldata _signature) internal pure returns (address) {
        return ECDSA.recover(_hash, _signature);
    }
}
