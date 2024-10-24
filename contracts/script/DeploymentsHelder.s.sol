// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { TaiyiCore } from "../src/TaiyiCore.sol";
import { TaiyiProposerRegistry } from "../src/TaiyiProposerRegistry.sol";
import "../src/TaiyiEscrow.sol";
import "../src/interfaces/ITaiyiCore.sol";

contract DeployHelder is Script, Test {
    function run() public {
        vm.startBroadcast();

        // 	0x83c8c0B395850bA55c830451Cfaca4F2A667a983 is just dummy address for testing
        TaiyiCore taiyiCore = new TaiyiCore(msg.sender, 1_718_967_600);

        emit log_address(address(taiyiCore));

        // ProposerRegistry taiyiProposerRegistry = new ProposerRegistry();
        // emit log_address(address(taiyiProposerRegistry));

        vm.stopBroadcast();
    }
}
