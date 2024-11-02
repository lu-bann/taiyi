// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { TaiyiCore } from "../src/TaiyiCore.sol";
import { TaiyiEscrow } from "../src/TaiyiEscrow.sol";
import { ITaiyiCore } from "../src/interfaces/ITaiyiCore.sol";
import { TipTx, PreconfTx, PreconfRequest } from "../src/interfaces/Types.sol";
import { PreconfRequestLib } from "../src/libs/PreconfRequestLib.sol";
import { Helper } from "../src/utils/Helper.sol";
import { PreconfRequestStatus } from "../src/interfaces/Types.sol";

contract TaiyiCoreTest is Test {
    using PreconfRequestLib for *;
    using Helper for bytes;

    TaiyiCore public taiyiCore;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal bobPrivatekey;
    uint256 internal coinbasePrivatekey;

    uint256 internal constant genesisTimestamp = 1_606_824_023;

    address user;
    address owner;
    address bob;
    address coinbase;

    event Exhausted(address indexed preconfer, uint256 amount);

    function setUp() public {
        userPrivatekey = 0x5678;
        ownerPrivatekey = 0x69420;
        bobPrivatekey = 0x1337;
        coinbasePrivatekey = 0x69422;

        user = vm.addr(userPrivatekey);
        owner = vm.addr(ownerPrivatekey);
        bob = vm.addr(bobPrivatekey);
        coinbase = vm.addr(coinbasePrivatekey);

        console.log("User address:", user);
        console.log("Owner address:", owner);
        console.log("bob address:", bob);
        vm.deal(user, 100 ether);
        vm.deal(owner, 100 ether);

        vm.warp(genesisTimestamp);

        // TODO: remove this address(0) with proposer registry address
        taiyiCore = new TaiyiCore(owner, genesisTimestamp, address(0));
    }

    function assertPreconfRequestStatus(bytes32 preconfRequestHash, PreconfRequestStatus expectedStatus) internal {
        uint8 status = uint8(taiyiCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(expectedStatus), "Unexpected PreconfRequest status");
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
        console.logBytes(tipTxSig);

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
        uint256 targetSlot = 10;
        TipTx memory tipTx = TipTx({
            gasLimit: 100_000,
            from: user,
            to: owner,
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0,
            targetSlot: targetSlot
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
        taiyiCore.deposit{ value: 4 ether }();

        uint256 balances = taiyiCore.balanceOf(user);
        console.log("User balance:", balances);
        vm.warp(genesisTimestamp + 12 * targetSlot);

        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.NonInitiated);

        vm.prank(owner);
        taiyiCore.settleRequest(preconfReq);
        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.Executed);

        uint256 bobBalance = bob.balance;
        assertEq(bobBalance, 1 ether);

        uint256 collectedTip = taiyiCore.getCollectedTip();
        assertEq(collectedTip, 0);

        taiyiCore.collectTip(preconfRequestHash);
        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.Collected);
        collectedTip = taiyiCore.getCollectedTip();
        assertEq(collectedTip, 3 ether);
    }

    function testExhaustFunction() public {
        TipTx memory tipTx = TipTx({
            gasLimit: 100_000,
            from: user,
            to: owner,
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0,
            targetSlot: 10
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
        taiyiCore.deposit{ value: 9 ether }();

        // Check balance before exhaust
        uint256 balanceBefore = taiyiCore.balanceOf(user);
        assertEq(balanceBefore, 9 ether);

        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.NonInitiated);

        vm.coinbase(coinbase);

        vm.prank(owner);
        taiyiCore.exhaust(preconfReq);
        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.Exhausted);

        assertEq(coinbase.balance, 100_000);

        taiyiCore.collectTip(preconfRequestHash);
        uint256 collectedTip = taiyiCore.getCollectedTip();
        assertEq(collectedTip, 1 ether);
        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.Collected);
    }
}
