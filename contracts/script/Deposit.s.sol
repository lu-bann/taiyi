// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { TaiyiCore } from "../src/TaiyiCore.sol";
import { ProposerRegistry } from "../src/TaiyiProposerRegistry.sol";
import "../src/TaiyiEscrow.sol";
import "../src/interfaces/ITaiyiCore.sol";

contract DeployDevnet is Script, Test {
    TaiyiEscrow taiyiEscrow;

    function run() public {
        vm.startBroadcast();
        address payable escrow_addr = payable(0x80326143C9157A6f3692634201475f3328e1Eb64);
        taiyiEscrow = TaiyiEscrow(escrow_addr);

        taiyiEscrow.deposit{ value: 10 }();

        vm.stopBroadcast();
    }
}
