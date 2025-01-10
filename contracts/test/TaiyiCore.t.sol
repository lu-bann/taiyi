// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/TaiyiCore.sol";
import { TaiyiEscrow } from "../src/TaiyiEscrow.sol";
import { ITaiyiCore } from "../src/interfaces/ITaiyiCore.sol";

import { PreconfRequestLib } from "../src/libs/PreconfRequestLib.sol";

import { PreconfRequestStatus } from "../src/types/CommonTypes.sol";
import {
    BlockspaceAllocation,
    PreconfRequestBType
} from "../src/types/PreconfRequestBTypes.sol";
import { Helper } from "../src/utils/Helper.sol";
import { Test, console } from "forge-std/Test.sol";

contract TaiyiCoreTest is Test {
    using PreconfRequestLib for *;
    using Helper for bytes;

    TaiyiCore public taiyiCore;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal coinbasePrivatekey;

    uint256 internal constant genesisTimestamp = 1_606_824_023;

    address user;
    address owner;
    address coinbase;
    bytes rawTx =
        hex"000000000000000000000000a83114a443da1cecefc50368531cace9f37fcccb0000000000000000000000006d2e03b7effeae98bd302a9f836d0d6ab000276600000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000005208000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000011100000000000000000000000000000000000000000000000000000000000000";

    event Exhausted(address indexed preconfer, uint256 amount);

    function setUp() public {
        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");
        (coinbase, coinbasePrivatekey) = makeAddrAndKey("coinbase");

        vm.deal(user, 100 ether);
        vm.deal(owner, 100 ether);

        vm.warp(genesisTimestamp);

        // TODO: remove this address(0) with proposer registry address
        taiyiCore = new TaiyiCore(owner, genesisTimestamp);
    }

    function assertPreconfRequestStatus(
        bytes32 preconfRequestHash,
        PreconfRequestStatus expectedStatus
    )
        internal
        view
    {
        uint8 status = uint8(taiyiCore.getPreconfRequestStatus(preconfRequestHash));
        assertEq(status, uint8(expectedStatus), "Unexpected PreconfRequest status");
    }

    function fulfillPreconfRequest(BlockspaceAllocation memory blockspaceAllocation)
        internal
        view
        returns (PreconfRequestBType memory preconfRequestBType)
    {
        bytes32 blockspaceHash = blockspaceAllocation.getBlockspaceAllocationHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivatekey, blockspaceHash);
        bytes memory blockspaceAllocationSignature = abi.encodePacked(r, s, v);

        (v, r, s) =
            vm.sign(ownerPrivatekey, blockspaceAllocationSignature.hashSignature());
        bytes memory gatewaySignedBlockspaceAllocation = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(ownerPrivatekey, rawTx.hashSignature());
        bytes memory gatewaySignedRawTx = abi.encodePacked(r, s, v);

        preconfRequestBType = PreconfRequestBType({
            blockspaceAllocation: blockspaceAllocation,
            blockspaceAllocationSignature: blockspaceAllocationSignature,
            gatewaySignedBlockspaceAllocation: gatewaySignedBlockspaceAllocation,
            rawTx: rawTx,
            gatewaySignedRawTx: gatewaySignedRawTx
        });
    }

    function testNormalWorkflow() public {
        uint256 targetSlot = 10;
        BlockspaceAllocation memory blockspaceAllocation = BlockspaceAllocation({
            gasLimit: 100_000,
            sender: user,
            recipient: owner,
            deposit: 1 ether,
            tip: 2 ether,
            targetSlot: targetSlot,
            blobCount: 1
        });

        PreconfRequestBType memory preconfReq =
            fulfillPreconfRequest(blockspaceAllocation);
        bytes32 preconfRequestHash = preconfReq.getPreconfRequestBTypeHash();
        vm.prank(user);
        taiyiCore.deposit{ value: 4 ether }();

        uint256 balances = taiyiCore.balanceOf(user);
        console.log("User balance:", balances);
        vm.warp(genesisTimestamp + 12 * targetSlot);

        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.NonInitiated);

        vm.prank(owner);
        taiyiCore.getTip(preconfReq);
        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.Executed);

        balances = taiyiCore.balanceOf(user);
        assertEq(balances, 1 ether);

        uint256 collectedTip = taiyiCore.getCollectedTip();
        assertEq(collectedTip, 0);

        taiyiCore.collectTip(preconfRequestHash);
        assertPreconfRequestStatus(preconfRequestHash, PreconfRequestStatus.Collected);
        collectedTip = taiyiCore.getCollectedTip();
        assertEq(collectedTip, 3 ether);
    }

    function testExhaustFunction() public {
        uint256 targetSlot = 10;
        BlockspaceAllocation memory blockspaceAllocation = BlockspaceAllocation({
            gasLimit: 100_000,
            sender: user,
            recipient: owner,
            deposit: 1 ether,
            tip: 2 ether,
            targetSlot: targetSlot,
            blobCount: 1
        });
        PreconfRequestBType memory preconfReq =
            fulfillPreconfRequest(blockspaceAllocation);
        bytes32 preconfRequestHash = preconfReq.getPreconfRequestBTypeHash();

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
