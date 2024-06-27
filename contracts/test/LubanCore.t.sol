// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { LubanCore } from "../src/LubanCore.sol";
import "src/LubanEscrow.sol";
import "src/interfaces/ILubanCore.sol";

contract LubanCoreTest is Test {
    LubanCore public lubanCore;
    LubanEscrow public lubanEscrow;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal preconferPrivatekey;

    address user;
    address owner;
    address preconfer;

    event Exhausted(address indexed preconfer, uint256 amount);

    function setUp() public {
        userPrivatekey = 0x5678;
        ownerPrivatekey = 0x69420;
        preconferPrivatekey = 0x0001;
        uint256 randomPrivate = 0x4321;

        user = vm.addr(userPrivatekey);
        owner = vm.addr(ownerPrivatekey);
        preconfer = vm.addr(preconferPrivatekey);
        address dummyAxiomV2Query = vm.addr(randomPrivate);

        vm.deal(user, 100 ether);
        vm.deal(preconfer, 100 ether);

        lubanCore = new LubanCore(owner, dummyAxiomV2Query, bytes32(0));
        lubanEscrow = lubanCore.getLubanEscrow();
    }

    function testPaymentAndEventEmissionGasCost() public {
        uint256 gasLimit = 60_000;

        vm.prank(address(this));
        uint256 gasCost = lubanCore.gasBurner(gasLimit);
        assertLt(gasCost, gasLimit, "Gas cost should be less than the gas limit");
    }

    function testExhaustFunction() public {
        ILubanCore.TipTx memory tipTx = ILubanCore.TipTx({
            gasLimit: 60_000,
            from: user,
            to: preconfer,
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0
        });

        bytes32 txHash = lubanCore.getTipTxHash(tipTx);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivatekey, txHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(preconferPrivatekey, bytes32(userSignature));
        bytes memory preconferSignature = abi.encodePacked(r, s, v);

        vm.prank(owner);
        lubanCore.registerPreconfer(preconfer);

        vm.prank(user);
        lubanEscrow.deposit{ value: 9 ether }();

        vm.prank(preconfer);
        lubanCore.exhaust(tipTx, userSignature, preconferSignature);

        assertEq(address(lubanCore).balance, 1 ether);
        assertEq(
            lubanCore.preconferTips(preconfer, bytes32(preconferSignature)),
            1 ether,
            "Preconfer balance should be 1 ether after exhaust"
        );
    }

    function testSettleRequestFunction() public {
        ILubanCore.TipTx memory tipTx = ILubanCore.TipTx({
            gasLimit: 60_000,
            from: user,
            to: preconfer,
            prePay: 1 ether,
            afterPay: 2 ether,
            nonce: 0
        });

        ILubanCore.PreconfConditions memory preconfConditions = ILubanCore.PreconfConditions({
            inclusionMetaData: ILubanCore.InclusionMeta({ startingBlockNumber: 5 }),
            orderingMetaData: ILubanCore.OrderingMeta({ txCount: 1, index: 1 }),
            blockNumber: 10
        });

        bytes32 tipTxAndPreconfConditionsHash = lubanCore.getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivatekey, tipTxAndPreconfConditionsHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes32 tipTxHash = lubanCore.getTipTxHash(tipTx);
        (v, r, s) = vm.sign(userPrivatekey, tipTxHash);
        bytes memory tipTxUserSignature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(preconferPrivatekey, bytes32(userSignature));
        bytes memory preconferSignature = abi.encodePacked(r, s, v);

        ILubanCore.PreconfRequest memory preconfReq = ILubanCore.PreconfRequest({
            tipTx: tipTx,
            prefConditions: preconfConditions,
            preconfTx: ILubanCore.PreconfTx({ to: preconfer, value: 1 ether, callData: "", ethTransfer: true }),
            tipTxSignature: tipTxUserSignature,
            initSignature: userSignature,
            preconferSignature: preconferSignature
        });

        vm.prank(owner);
        lubanCore.registerPreconfer(preconfer);

        vm.prank(user);
        lubanEscrow.deposit{ value: 9 ether }();

        vm.roll(10);
        vm.prank(preconfer);
        lubanCore.settleRequest{ value: preconfReq.preconfTx.value }(preconfReq);

        assertEq(address(lubanCore).balance, 3 ether);
        assertEq(
            lubanCore.preconferTips(preconfer, bytes32(preconferSignature)),
            3 ether,
            "Preconfer balance should be 1 ether after exhaust"
        );
    }
}
