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
                TaiyiParameterManager.initialize.selector, owner, 1, 64, 256
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
        assertEq(taiyiParameterManager.blockhashLookback(), 256);
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
    //  Test: Owner can set blockhash lookback
    // =========================================
    function testOwnerCanSetBlockhashLookback() public {
        vm.prank(owner);
        taiyiParameterManager.setBlockhashLookback(128);
        assertEq(taiyiParameterManager.blockhashLookback(), 128);
    }

    // =========================================
    //  Test: User is not authorized to set blockhash lookback
    // =========================================
    function testUserCannotSetBlockhashLookback() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiParameterManager.setBlockhashLookback(128);
    }
}
