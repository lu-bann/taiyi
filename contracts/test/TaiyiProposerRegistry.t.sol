// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../src/TaiyiProposerRegistry.sol";

contract TaiyiProposerRegistryTest is Test {
    TaiyiProposerRegistry public registry;
    address public proposer1 = address(0x1);
    address public proposer2 = address(0x2);
    bytes public blsPubKey1 = hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    bytes public blsPubKey2 = hex"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    function setUp() public {
        registry = new TaiyiProposerRegistry();
    }

    // function testOptInRequires32Eth() public {
    //     vm.deal(proposer1, TaiyiProposerRegistryLib.STAKE_AMOUNT);
    //     vm.prank(proposer1);
    //     registry.optIn{ value: TaiyiProposerRegistryLib.STAKE_AMOUNT }(blsPubKey1);

    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(TaiyiProposerRegistry.ProposerStatus.OptIn),
    //         "Proposer status should be OptIn"
    //     );
    //     assertEq(address(registry).balance, TaiyiProposerRegistryLib.STAKE_AMOUNT);
    // }

    // function testCannotWithdrawBeforeCooldown() public {
    //     vm.deal(proposer1, TaiyiProposerRegistryLib.STAKE_AMOUNT);
    //     vm.startPrank(proposer1);
    //     registry.optIn{ value: TaiyiProposerRegistryLib.STAKE_AMOUNT }(blsPubKey1);

    //     registry.initOptOut();

    //     vm.expectRevert("Cooldown not elapsed");
    //     registry.confirmOptOut();

    //     vm.warp(block.timestamp + 23 hours);
    //     vm.expectRevert("Cooldown not elapsed");
    //     registry.confirmOptOut();

    //     vm.warp(block.timestamp + 2 hours);
    //     registry.confirmOptOut();
    //     assertEq(proposer1.balance, TaiyiProposerRegistryLib.STAKE_AMOUNT);
    //     vm.stopPrank();
    // }

    // function testOptOutThenOptInLater() public {
    //     vm.deal(proposer1, 64 ether);
    //     vm.startPrank(proposer1);

    //     // First opt-in
    //     registry.optIn{ value: TaiyiProposerRegistryLib.STAKE_AMOUNT }(blsPubKey1);
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(TaiyiProposerRegistry.ProposerStatus.OptIn),
    //         "Proposer status should be OptIn"
    //     );

    //     // Opt-out process
    //     registry.initOptOut();
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(TaiyiProposerRegistry.ProposerStatus.OptingOut),
    //         "Proposer status should be OptingOut"
    //     );

    //     vm.warp(block.timestamp + 1 days + 1);
    //     registry.confirmOptOut();
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(ProposerRegistry.ProposerStatus.OptedOut),
    //         "Proposer status should be OptedOut"
    //     );

    //     // Opt-in again
    //     registry.optIn{ value: ProposerRegistryLib.STAKE_AMOUNT }(blsPubKey1);
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(ProposerRegistry.ProposerStatus.OptIn),
    //         "Proposer status should be OptIn"
    //     );

    //     vm.stopPrank();
    // }

    // function testProposerStatusAfterOptOut() public {
    //     vm.deal(proposer1, 32 ether);
    //     vm.startPrank(proposer1);

    //     registry.optIn{ value: ProposerRegistryLib.STAKE_AMOUNT }(blsPubKey1);
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(ProposerRegistry.ProposerStatus.OptIn),
    //         "Proposer status should be OptIn"
    //     );

    //     registry.initOptOut();
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(ProposerRegistry.ProposerStatus.OptingOut),
    //         "Proposer status should be OptingOut"
    //     );

    //     vm.warp(block.timestamp + 1 days + 1);
    //     registry.confirmOptOut();
    //     assertEq(
    //         uint8(registry.getProposerStatus(blsPubKey1)),
    //         uint8(ProposerRegistry.ProposerStatus.OptedOut),
    //         "Proposer status should be OptedOut"
    //     );

    //     vm.stopPrank();
    // }
}
