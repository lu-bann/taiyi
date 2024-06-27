// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/LubanEscrow.sol";
import "../src/LubanCore.sol";
import "../src/interfaces/ILubanCore.sol";

contract LubanEscrowTest is Test {
    LubanEscrow escrow;
    LubanCore core;
    address user;
    address lubanCore;
    address owner;

    uint256 internal lubanCorePrivatekey;
    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;

    function setUp() public {
        userPrivatekey = 0x5678;
        ownerPrivatekey = 0x1234;
        uint256 randomPrivatekey = 0x4321;

        user = vm.addr(userPrivatekey);
        owner = vm.addr(ownerPrivatekey);
        address dummyAxiomV2Query = vm.addr(randomPrivatekey);

        vm.deal(user, 100 ether);

        core = new LubanCore(owner, dummyAxiomV2Query, bytes32(0));
        escrow = core.getLubanEscrow();
    }

    function testDeposit() public {
        vm.prank(user);
        escrow.deposit{ value: 1 ether }();

        assertEq(escrow.balances(user), 1 ether, "Balance should be 1 ether after deposit");
        assertEq(escrow.lockBlockOf(user), type(uint256).max, "Lock block should be max after deposit");
    }

    function testWithdrawLocked() public {
        vm.startPrank(user);
        escrow.deposit{ value: 1 ether }();
        vm.stopPrank();

        vm.expectRevert("Withdrawal is locked");
        vm.prank(user);
        escrow.withdraw(1 ether);
    }

    function testWithdrawAfterLock() public {
        vm.prank(user);
        escrow.deposit{ value: 1 ether }();

        vm.prank(user);
        escrow.requestWithdraw(1 ether);

        vm.roll(block.number + 64);
        vm.prank(user);
        escrow.withdraw(1 ether);

        assertEq(escrow.balances(user), 0, "Balance should be zero after withdrawal");
    }

    // Helper function to simulate signing a TipTx according to EIP-712
    function signTipTx(ILubanCore.TipTx memory tipTx) internal view returns (bytes memory) {
        // Retrieve the domain separator from LubanCore
        bytes32 digest = core.getTipTxHash(tipTx);
        // Using LubanCore's private key to sign the digest for testing
        // In a real scenario, the user's private key would be used
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivatekey, digest);
        return abi.encodePacked(r, s, v);
    }

    function testPayoutPreExec() public {
        // Simulate a user depositing ether into the escrow
        vm.startPrank(user);
        escrow.deposit{ value: 3 ether }();
        vm.stopPrank();

        ILubanCore.TipTx memory tipTx = ILubanCore.TipTx({
            gasLimit: 21_000,
            from: user,
            to: address(core),
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0
        });

        bytes memory signature = signTipTx(tipTx);

        // Payout with preExec set to true
        vm.prank(address(core));
        escrow.payout(tipTx, signature, false, bytes(""));

        // Check balances after preExec payout
        assertEq(address(escrow).balance, 2 ether, "Escrow should have 2 ether after preExec payout");
        assertEq(escrow.balances(user), 2 ether, "User should have 2 ether left in escrow");
    }

    function testPayoutAfterExec() public {
        // Setup deposit
        vm.startPrank(user);
        escrow.deposit{ value: 3 ether }();
        vm.stopPrank();

        // Create a TipTx struct instance and simulate signing process
        ILubanCore.TipTx memory tipTx = ILubanCore.TipTx({
            gasLimit: 21_000,
            from: user,
            to: address(core),
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0
        });

        bytes memory signature = signTipTx(tipTx);

        // Payout with afterExec set to true (total should be transferred)
        vm.prank(address(core));
        escrow.payout(tipTx, signature, true, bytes(""));

        // Check balances after full execution payout
        assertEq(address(escrow).balance, 0, "Escrow should have no ether after full payout");
        assertEq(escrow.balances(user), 0, "User should have no ether left in escrow");
    }
}
