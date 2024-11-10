// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { TaiyiCore } from "../src/TaiyiCore.sol";
import { TaiyiProposerRegistry } from "../src/TaiyiProposerRegistry.sol";
import "../src/TaiyiEscrow.sol";
import "../src/interfaces/ITaiyiCore.sol";

contract Deploy is Script, Test {
    function run() public {
        vm.startBroadcast();

        TaiyiCore taiyiCore = new TaiyiCore();
        emit log_address(address(taiyiCore));

        vm.stopBroadcast();
    }
}
