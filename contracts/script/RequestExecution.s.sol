// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { LubanCore } from "../src/LubanCore.sol";
import { LubanEscrow } from "../src/LubanEscrow.sol";
import { ILubanCore } from "../src/interfaces/ILubanCore.sol";
import { PreconfRequestLib } from "../src/interfaces/PreconfRequestLib.sol";
import { PreconfRequest, TipTx, PreconfTx } from "../src/interfaces/PreconfRequest.sol";

contract DeployTest is Test {
    using PreconfRequestLib for *;

    LubanCore public lubanCore;
    LubanEscrow public lubanEscrow;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal preconferPrivatekey;

    address user;
    address owner;
    address preconfer;

    uint8 v;
    bytes32 r;
    bytes32 s;

    event Exhausted(address indexed preconfer, uint256 amount);

    function setUp() public {
        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");
        (preconfer, preconferPrivatekey) = makeAddrAndKey("preconfer");

        console.log("user:      ", user, " | balance: ", user.balance);
        console.log("owner:     ", owner, " | balance: ", owner.balance);
        console.log("preconfer: ", preconfer, " | balance: ", preconfer.balance);

        // vm.deal(user, 100 ether);
        // vm.deal(preconfer, 100 ether);

        // lubanCore = new LubanCore(owner);
        // lubanEscrow = lubanCore.getLubanEscrow();
    }

    function run() public {
        //////////////////////////
        // Owner
        //////////////////////////
        vm.startBroadcast(ownerPrivatekey);
        lubanCore = LubanCore(payable(0x88F59F8826af5e695B13cA934d6c7999875A9EeA));
        console.log("Luban Core Address:   ", address(lubanCore));

        // check preconfer
        vm.stopBroadcast();

        //////////////////////////
        // User
        //////////////////////////
        vm.startBroadcast(userPrivatekey);
        TipTx memory tipTx = TipTx({
            gasLimit: 100_000,
            from: user,
            to: preconfer,
            prePay: 0.1 ether,
            afterPay: 0.5 ether,
            nonce: 0,
            target_slot: 10
        });

        bytes32 tipTxHash = tipTx.getTipTxHash();
        (v, r, s) = vm.sign(userPrivatekey, tipTxHash);
        bytes memory tipTxUserSignature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(preconferPrivatekey, bytes32(tipTxUserSignature));
        bytes memory preconferSignature = abi.encodePacked(r, s, v);

        PreconfTx memory preconfTx = PreconfTx({
            from: user,
            to: preconfer,
            value: 0.1 ether,
            callData: "",
            callGasLimit: 100_000,
            nonce: 0,
            signature: ""
        });
        bytes32 preconfTxHash = preconfTx.getPreconfTxHash();
        (v, r, s) = vm.sign(userPrivatekey, bytes32(preconfTxHash));
        bytes memory preconfTxSignature = abi.encodePacked(r, s, v);
        preconfTx.signature = preconfTxSignature;

        PreconfRequest memory preconfReq = PreconfRequest({
            tipTx: tipTx,
            preconfTx: preconfTx,
            tipTxSignature: "",
            preconferSignature: preconferSignature,
            preconfReqSignature: ""
        });

        // lubanEscrow.deposit{ value: 1 ether }();

        console.log("user balance:    ", lubanEscrow.balances(user));
        // console.log("user lock block: ", lubanEscrow.lockBlock(user));
        // console.log("user nonce:      ", lubanEscrow.nonce(user));
        vm.stopBroadcast();

        // vm.startBroadcast(preconferPrivatekey);
        //     lubanCore.settleRequest{value: preconfReq.preconfTx.value}(preconfReq);
        // vm.stopBroadcast();
    }
}
