// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { LubanCore } from "../src/LubanCore.sol";
import { LubanEscrow } from "../src/LubanEscrow.sol";
import { ILubanCore } from "../src/interfaces/ILubanCore.sol";
import { TipTx, PreconfTx, PreconfRequest } from "../src/interfaces/Types.sol";
import { PreconfRequestLib } from "../src/libs/PreconfRequestLib.sol";
import { Helper } from "../src/utils/Helper.sol";
import { PreconfRequestStatus } from "../src/interfaces/Types.sol";

contract LubanCoreTest is Test {
    using PreconfRequestLib for *;
    using Helper for bytes;

    LubanCore public lubanCore;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal bobPrivatekey;

    uint256 internal constant genesisTimestamp = 1_606_824_023;

    address user;
    address owner;
    address bob;

    event Exhausted(address indexed preconfer, uint256 amount);

    function setUp() public {
        userPrivatekey = 0x5678;
        ownerPrivatekey = 0x69420;
        bobPrivatekey = 0x1337;

        user = vm.addr(userPrivatekey);
        owner = vm.addr(ownerPrivatekey);
        bob = vm.addr(bobPrivatekey);

        console.log("User address:", user);
        console.log("Owner address:", owner);
        console.log("bob address:", bob);
        vm.deal(user, 100 ether);
        vm.deal(owner, 100 ether);

        vm.warp(genesisTimestamp);
        lubanCore = new LubanCore(owner, genesisTimestamp);
    }

    function fulfillPreconfRequest(
        TipTx memory tipTx,
        PreconfTx memory preconfTx
    )
        internal
        returns (PreconfRequest memory)
    {
        bytes32 txHash = tipTx.getTipTxHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivatekey, txHash);
        bytes memory tipTxSig = abi.encodePacked(r, s, v);

        bytes32 preconfTxHash = preconfTx.getPreconfTxHash();
        (v, r, s) = vm.sign(userPrivatekey, preconfTxHash);
        bytes memory preconfTxSig = abi.encodePacked(r, s, v);
        preconfTx.signature = preconfTxSig;

        (v, r, s) = vm.sign(ownerPrivatekey, tipTxSig.hashSignature());
        bytes memory preconferSignature = abi.encodePacked(r, s, v);
        PreconfRequest memory preconfReq = PreconfRequest({
            tipTx: tipTx,
            preconfTx: preconfTx,
            tipTxSignature: tipTxSig,
            preconferSignature: preconferSignature,
            preconfReqSignature: ""
        });

        bytes32 preconfReqHash = preconfReq.getPreconfRequestHash();
        (v, r, s) = vm.sign(ownerPrivatekey, preconfReqHash);
        bytes memory preconfReqSig = abi.encodePacked(r, s, v);
        preconfReq.preconfReqSignature = preconfReqSig;
        return preconfReq;
    }

    function testNormalWorkflow() public {
        uint256 target_slot = 10;
        TipTx memory tipTx = TipTx({
            gasLimit: 100_000,
            from: user,
            to: owner,
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0,
            target_slot: target_slot
        });

        PreconfTx memory preconfTx = PreconfTx({
            from: user,
            to: bob,
            value: 1 ether,
            callData: "",
            callGasLimit: 100_000,
            nonce: 0,
            signature: ""
        });

        PreconfRequest memory preconfReq = fulfillPreconfRequest(tipTx, preconfTx);
        bytes32 preconfRequestHash = preconfReq.getPreconfRequestHash();
        vm.prank(user);
        lubanCore.deposit{ value: 4 ether }();

        uint256 balances = lubanCore.balanceOf(user);
        console.log("User balance:", balances);
        vm.warp(genesisTimestamp + 12 * target_slot);

        uint8 status = uint8(lubanCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(PreconfRequestStatus.NonInitiated));

        vm.prank(owner);
        lubanCore.settleRequest(preconfReq);
        status = uint8(lubanCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(PreconfRequestStatus.Executed));

        uint256 bobBalance = bob.balance;
        assertEq(bobBalance, 1 ether);

        uint256 collectedTip = lubanCore.getCollectedTip();
        assertEq(collectedTip, 0);

        lubanCore.collectTip(preconfRequestHash);
        status = uint8(lubanCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(PreconfRequestStatus.Collected));
        collectedTip = lubanCore.getCollectedTip();
        assertEq(collectedTip, 3 ether);
    }

    function testExhaustFunction() public {
        uint256 target_slot = 10;
        TipTx memory tipTx = TipTx({
            gasLimit: 100_000,
            from: user,
            to: owner,
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0,
            target_slot: 10
        });
        PreconfTx memory preconfTx = PreconfTx({
            from: user,
            to: bob,
            value: 1 ether,
            callData: "",
            callGasLimit: 100_000,
            nonce: 0,
            signature: ""
        });
        PreconfRequest memory preconfReq = fulfillPreconfRequest(tipTx, preconfTx);
        bytes32 preconfRequestHash = preconfReq.getPreconfRequestHash();

        vm.prank(user);
        lubanCore.deposit{ value: 9 ether }();

        // Check balance before exhaust
        uint256 balanceBefore = lubanCore.balanceOf(user);
        assertEq(balanceBefore, 9 ether);

        uint8 status = uint8(lubanCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(PreconfRequestStatus.NonInitiated));

        vm.prank(owner);
        lubanCore.exhaust(preconfReq);
        status = uint8(lubanCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(PreconfRequestStatus.Exhausted));

        lubanCore.collectTip(preconfRequestHash);
        uint256 collectedTip = lubanCore.getCollectedTip();
        assertEq(collectedTip, 1 ether);
        status = uint8(lubanCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(PreconfRequestStatus.Collected));
    }
}
