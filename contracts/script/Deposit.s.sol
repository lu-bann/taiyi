// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LubanCore } from "../src/LubanCore.sol";
import { ProposerRegistry } from "../src/LubanProposerRegistry.sol";
import "../src/LubanEscrow.sol";
import "../src/interfaces/ILubanCore.sol";

contract DeployDevnet is Script, Test {
    LubanEscrow lubanEscrow;

    function run() public {
        vm.startBroadcast();
        address payable escrow_addr = payable(0x80326143C9157A6f3692634201475f3328e1Eb64);
        lubanEscrow = LubanEscrow(escrow_addr);

        lubanEscrow.deposit{ value: 10 }();

        vm.stopBroadcast();
    }
}
