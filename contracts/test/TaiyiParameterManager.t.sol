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
    address internal TAIYI_CORE_ADDRESS = 0x1127A1E8248ae0Ee1D5F1C7094fFD7DC37Cbe714;

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
                12,
                TAIYI_CORE_ADDRESS
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
        assertEq(taiyiParameterManager.taiyiCore(), TAIYI_CORE_ADDRESS);
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

    // =========================================
    //  Test: Owner can set slot time
    // =========================================
    function testOwnerCanSetSlotTime() public {
        vm.prank(owner);
        taiyiParameterManager.setSlotTime(42);
        assertEq(taiyiParameterManager.slotTime(), 42);
    }

    // =========================================
    //  Test: User is not authorized to set slot time
    // =========================================
    function testUserCannotSetSlotTime() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setSlotTime(42);
    }

    // =========================================
    //  Test: Owner can set taiyi core address
    // =========================================
    function testOwnerCanSetTaiyiCoreAddress() public {
        vm.prank(owner);
        taiyiParameterManager.setTaiyiCore(0x7293b38a3162e425136d96225ee8984468372D6A);
        assertEq(
            taiyiParameterManager.taiyiCore(), 0x7293b38a3162e425136d96225ee8984468372D6A
        );
    }

    // =========================================
    //  Test: User is not authorized to set taiyi core address
    // =========================================
    function testUserCannotSetTaiyiCoreAddress() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setTaiyiCore(0x7293b38a3162e425136d96225ee8984468372D6A);
    }
}
