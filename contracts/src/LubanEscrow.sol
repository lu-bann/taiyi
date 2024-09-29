// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/console.sol";

import "open-zeppelin/utils/ReentrancyGuard.sol";
import "open-zeppelin/utils/cryptography/ECDSA.sol";
import "open-zeppelin/utils/cryptography/MessageHashUtils.sol";
import { TipTx } from "./interfaces/PreconfRequest.sol";
import { PreconfRequest } from "./interfaces/PreconfRequest.sol";
import { PreconfTx } from "./interfaces/PreconfRequest.sol";
import { PreconfRequestLib } from "./interfaces/PreconfRequestLib.sol";
import { Helper } from "./Helper.sol";

contract LubanEscrow is ReentrancyGuard {
    using PreconfRequestLib for *;
    using ECDSA for bytes32;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockBlock;

    uint256 public constant LOCK_PERIOD = 64;
    uint256 public maxUint256 = type(uint256).max;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event PaymentMade(address indexed from, uint256 amount, bool isAfterExec);
    event RequestedWithdraw(address indexed user, uint256 amount);

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

    function payout(TipTx calldata tipTx, bool isAfterExec) internal nonReentrant returns (uint256 amount) {
        amount = isAfterExec ? tipTx.prePay + tipTx.afterPay : tipTx.prePay;
        require(balances[tipTx.from] >= amount, "Insufficient balance");

        balances[tipTx.from] -= amount;
    }
}
