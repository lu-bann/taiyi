// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import { TaiyiParameterManager } from "../src/TaiyiParameterManager.sol";

import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract TaiyiParameterManagerTest is Test {
    address user;
    address owner;
    address proxyAdmin;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal proxyAdminPrivatekey;
    uint256 internal SEPOLIA_GENESIS_TIMESTAMP = 1_655_733_600;

    TaiyiParameterManager taiyiParameterManager;

    function setUp() public {
        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");
        (proxyAdmin, proxyAdminPrivatekey) = makeAddrAndKey("proxyAdmin");

        vm.startPrank(owner);

        // Deploy TaiyiParameterManager as an upgradeable instance
        TaiyiParameterManager taiyiParameterManagerImpl = new TaiyiParameterManager();
        TransparentUpgradeableProxy taiyiParameterManagerProxy = new TransparentUpgradeableProxy(
            address(taiyiParameterManagerImpl),
            proxyAdmin,
            abi.encodeWithSelector(
                TaiyiParameterManager.initialize.selector,
                owner,
                1,
                64,
                256,
                SEPOLIA_GENESIS_TIMESTAMP,
                12
            )
        );
        taiyiParameterManager = TaiyiParameterManager(address(taiyiParameterManagerProxy));

        vm.stopPrank();
    }

    // =========================================
    //  Test: Verify initialization parameters
    // =========================================
    function testInitialization() public {
        assertEq(taiyiParameterManager.owner(), owner);
        assertEq(taiyiParameterManager.challengeBond(), 1);
        assertEq(taiyiParameterManager.challengeMaxDuration(), 64);
        assertEq(taiyiParameterManager.challengeCreationWindow(), 256);
        assertEq(taiyiParameterManager.genesisTimestamp(), SEPOLIA_GENESIS_TIMESTAMP);
        assertEq(taiyiParameterManager.slotTime(), 12);
    }

    // =========================================
    //  Test: Owner can set challenge bond
    // =========================================
    function testOwnerCanSetChallengeBond() public {
        vm.prank(owner);
        taiyiParameterManager.setChallengeBond(5);
        assertEq(taiyiParameterManager.challengeBond(), 5);
    }

    // =========================================
    //  Test: User is not authorized to set challenge bond
    // =========================================
    function testUserCannotSetChallengeBond() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setChallengeBond(5);
    }

    // =========================================
    //  Test: Owner can set challenge max duration
    // =========================================
    function testOwnerCanSetChallengeMaxDuration() public {
        vm.prank(owner);
        taiyiParameterManager.setChallengeMaxDuration(32);
        assertEq(taiyiParameterManager.challengeMaxDuration(), 32);
    }

    // =========================================
    //  Test: User is not authorized to set challenge max duration
    // =========================================
    function testUserCannotSetChallengeMaxDuration() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setChallengeMaxDuration(32);
    }

    // =========================================
    //  Test: Owner can set challenge creation window
    // =========================================
    function testOwnerCanSetChallengeCreationWindow() public {
        vm.prank(owner);
        taiyiParameterManager.setChallengeCreationWindow(128);
        assertEq(taiyiParameterManager.challengeCreationWindow(), 128);
    }

    // =========================================
    //  Test: User is not authorized to set challenge creation window
    // =========================================
    function testUserCannotSetChallengeCreationWindow() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setChallengeCreationWindow(128);
    }

    // =========================================
    //  Test: Owner can set genesis timestamp
    // =========================================
    function testOwnerCanSetGenesisTimestamp() public {
        vm.prank(owner);
        taiyiParameterManager.setGenesisTimestamp(1_616_508_000);
        assertEq(taiyiParameterManager.genesisTimestamp(), 1_616_508_000);
    }

    // =========================================
    //  Test: User is not authorized to set genesis timestamp
    // =========================================
    function testUserCannotSetGenesisTimestamp() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setGenesisTimestamp(1_616_508_000);
    }
}
