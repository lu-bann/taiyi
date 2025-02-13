// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/TaiyiCore.sol";
import { TaiyiEscrow } from "../src/TaiyiEscrow.sol";
import { ITaiyiCore } from "../src/interfaces/ITaiyiCore.sol";

import { PreconfRequestLib } from "../src/libs/PreconfRequestLib.sol";
import {
    BlockspaceAllocation,
    PreconfRequestBType
} from "../src/types/PreconfRequestBTypes.sol";
import { Helper } from "../src/utils/Helper.sol";
import { Test, console } from "forge-std/Test.sol";

contract DeployTest is Test {
    using PreconfRequestLib for BlockspaceAllocation;
    using Helper for *;

    TaiyiCore public taiyiCore;
    TaiyiEscrow public taiyiEscrow;

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
    }

    function signRawTx(bytes memory _rawTx) internal view returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) =
            vm.sign(preconferPrivatekey, keccak256(_rawTx));
        return abi.encodePacked(_r, _s, _v);
    }

    function run() public {
        //////////////////////////
        // Owner
        //////////////////////////
        vm.startBroadcast(ownerPrivatekey);
        taiyiCore = TaiyiCore(payable(0x88F59F8826af5e695B13cA934d6c7999875A9EeA));
        console.log("Taiyi Core Address:   ", address(taiyiCore));

        // check preconfer
        vm.stopBroadcast();

        //////////////////////////
        // User
        //////////////////////////
        vm.startBroadcast(userPrivatekey);
        BlockspaceAllocation memory blockspaceAllocation = BlockspaceAllocation({
            gasLimit: 100_000,
            sender: user,
            recipient: preconfer,
            deposit: 0.1 ether,
            tip: 0.1 ether,
            targetSlot: 10,
            blobCount: 1
        });

        bytes32 blockspaceAllocationHash =
            blockspaceAllocation.getBlockspaceAllocationHash();
        (v, r, s) = vm.sign(userPrivatekey, blockspaceAllocationHash);
        bytes memory blockspaceAllocationUserSignature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(
            preconferPrivatekey, blockspaceAllocationUserSignature.hashSignature()
        );

        console.log("user balance:    ", taiyiEscrow.balanceOf(user));
        vm.stopBroadcast();
    }
}
