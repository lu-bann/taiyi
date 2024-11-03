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

        address payable taiyiCoreAddr = payable(vm.envAddress("TAIYI_CORE"));
        console.log("taiyi core: ", taiyiCoreAddr);

        TaiyiCore taiyiCore = TaiyiCore(taiyiCoreAddr);

        taiyiCore.registerPreconfer(msg.sender);

        vm.stopBroadcast();
    }
}
