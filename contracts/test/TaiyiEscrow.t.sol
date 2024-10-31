// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/TaiyiEscrow.sol";
import "../src/TaiyiCore.sol";
import "../src/interfaces/ITaiyiCore.sol";
import "../src/libs/PreconfRequestLib.sol";

contract TaiyiEscrowTest is Test {
    using PreconfRequestLib for *;

    TaiyiCore core;
    address user;
    address taiyiCore;
    address owner;

    uint256 internal taiyiCorePrivatekey;
    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;

    function setUp() public {
        userPrivatekey = 0x5678;
        ownerPrivatekey = 0x1234;

        user = vm.addr(userPrivatekey);
        owner = vm.addr(ownerPrivatekey);

        vm.deal(user, 100 ether);

        // TODO: remove this address(0) with proposer registry address
        core = new TaiyiCore(owner, 1_606_824_023, address(0));
    }

    function testDeposit() public {
        vm.prank(user);
        core.deposit{ value: 1 ether }();

        assertEq(core.balances(user), 1 ether, "Balance should be 1 ether after deposit");
        assertEq(core.lockBlockOf(user), type(uint256).max, "Lock block should be max after deposit");
    }

    function testWithdrawLocked() public {
        vm.startPrank(user);
        core.deposit{ value: 1 ether }();
        vm.stopPrank();

        vm.expectRevert("Withdrawal is locked");
        vm.prank(user);
        core.withdraw(1 ether);
    }

    function testWithdrawAfterLock() public {
        vm.prank(user);
        core.deposit{ value: 1 ether }();

        vm.prank(user);
        core.requestWithdraw(1 ether);

        vm.roll(block.number + 64);
        vm.prank(user);
        core.withdraw(1 ether);

        assertEq(core.balances(user), 0, "Balance should be zero after withdrawal");
    }
}
