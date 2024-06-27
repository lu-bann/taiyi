// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { LubanCore } from "../src/LubanCore.sol";
import "src/LubanEscrow.sol";
import "src/interfaces/ILubanCore.sol";

contract DeployTest is Test {
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
        console.log("Luban Escrow Address: ", address(lubanCore.getLubanEscrow()));

        // check preconfer
        require(lubanCore.preconferList(preconfer), "preconfer is not yet set");
        vm.stopBroadcast();

        //////////////////////////
        // User
        //////////////////////////
        vm.startBroadcast(userPrivatekey);
        ILubanCore.TipTx memory tipTx = ILubanCore.TipTx({
            gasLimit: 60_000,
            from: user,
            to: preconfer,
            prePay: 0.1 ether,
            afterPay: 0.5 ether,
            nonce: 0
        });

        ILubanCore.PreconfConditions memory preconfConditions = ILubanCore.PreconfConditions({
            inclusionMetaData: ILubanCore.InclusionMeta({ startingBlockNumber: 5 }),
            orderingMetaData: ILubanCore.OrderingMeta({ txCount: 1, index: 1 }),
            blockNumber: 10
        });

        bytes32 tipTxAndPreconfConditionsHash = lubanCore.getTipTxAndPreconfConditionsHash(tipTx, preconfConditions);
        (v, r, s) = vm.sign(userPrivatekey, tipTxAndPreconfConditionsHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes32 tipTxHash = lubanCore.getTipTxHash(tipTx);
        (v, r, s) = vm.sign(userPrivatekey, tipTxHash);
        bytes memory tipTxUserSignature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(preconferPrivatekey, bytes32(userSignature));
        bytes memory preconferSignature = abi.encodePacked(r, s, v);

        ILubanCore.PreconfRequest memory preconfReq = ILubanCore.PreconfRequest({
            tipTx: tipTx,
            prefConditions: preconfConditions,
            preconfTx: ILubanCore.PreconfTx({ to: preconfer, value: 0.1 ether, callData: "", ethTransfer: true }),
            tipTxSignature: tipTxUserSignature,
            initSignature: userSignature,
            preconferSignature: preconferSignature
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
