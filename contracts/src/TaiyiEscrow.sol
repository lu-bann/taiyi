// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/console.sol";

import { TaiyiEscrowStorage } from "./storage/TaiyiEscrowStorage.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { PreconfRequestLib } from "./libs/PreconfRequestLib.sol";

import { BlockspaceAllocation } from "./types/PreconfRequestBTypes.sol";
import { Helper } from "./utils/Helper.sol";
import { ReentrancyGuardUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

import { ECDSA } from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from
    "@openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

abstract contract TaiyiEscrow is
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    TaiyiEscrowStorage
{
    using PreconfRequestLib for *;
    using ECDSA for bytes32;

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
        lockBlock[msg.sender] = MAX_UINT256;
        emit Deposited(msg.sender, msg.value);
    }

    /// @dev to withdraw a user needs to call requestWithdraw first
    ///      to record the block number at which the withdrawal was requested
    /// @notice calling deposit after requestWithdra will reset the lockBlock to
    /// maxUint256
    /// @param amount The amount to withdraw
    function requestWithdraw(uint256 amount) public {
        require(
            balances[msg.sender] >= amount, "Insufficient balance to request withdraw"
        );
        lockBlock[msg.sender] = block.number;
        emit RequestedWithdraw(msg.sender, amount);
    }

    /// @dev Withdraws the amount requested by the user
    /// @notice The lockBlock is reset to maxUint256 after withdrawal
    /// @param amount The amount to withdrawal
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(
            lockBlock[msg.sender] != MAX_UINT256
                && block.number >= lockBlock[msg.sender] + LOCK_PERIOD,
            "Withdrawal is locked"
        );
        balances[msg.sender] -= amount;
        (bool sent,) = payable(msg.sender).call{ value: amount }("");
        require(sent, "Failed to send Ether");
        lockBlock[msg.sender] = MAX_UINT256;
        emit Withdrawn(msg.sender, amount);
    }

    /// @dev Handles the payout of a blockspace allocation.
    /// @param blockspaceAllocation The blockspace allocation containing the payout details.
    /// @param isAfterExec A boolean indicating if the payout is after execution.
    /// @return amount The amount to be paid out.
    ///
    /// If isAfterExec is true, returns deposit + tip amount.
    /// If isAfterExec is false, returns only deposit amount.
    /// Deducts the amount from sender's balance after checking for sufficient funds.
    function payout(
        BlockspaceAllocation calldata blockspaceAllocation,
        bool isAfterExec
    )
        internal
        returns (uint256 amount)
    {
        amount = isAfterExec
            ? blockspaceAllocation.deposit + blockspaceAllocation.tip
            : blockspaceAllocation.deposit;
        require(balances[blockspaceAllocation.sender] >= amount, "Insufficient balance");
        balances[blockspaceAllocation.sender] -= amount;
    }
}
