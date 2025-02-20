// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/TaiyiCore.sol";
import "../src/TaiyiEscrow.sol";
import "../src/interfaces/ITaiyiCore.sol";
import "../src/libs/PreconfRequestLib.sol";

import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

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
        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");

        vm.deal(user, 100 ether);

        // TODO: remove this address(0) with proposer registry address
        core = new TaiyiCore();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(core),
            owner,
            abi.encodeWithSelector(TaiyiCore.initialize.selector, owner)
        );
        core = TaiyiCore(payable(address(proxy)));
    }

    function testDeposit() public {
        vm.prank(user);
        core.deposit{ value: 1 ether }();

        assertEq(core.balanceOf(user), 1 ether, "Balance should be 1 ether after deposit");
        assertEq(
            core.lockBlockOf(user),
            type(uint256).max,
            "Lock block should be max after deposit"
        );
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

        assertEq(core.balanceOf(user), 0, "Balance should be zero after withdrawal");
    }
}
