// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Test, console } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LubanCore } from "../src/LubanCore.sol";
import { ProposerRegistry } from "../src/LubanProposerRegistry.sol";
import "src/LubanEscrow.sol";
import "src/interfaces/ILubanCore.sol";

contract DeployDevnet is Script, Test {
    function run() public {
        vm.startBroadcast();

        // 	0x83c8c0B395850bA55c830451Cfaca4F2A667a983 is just dummy address for testing
        LubanCore lubanCore = new LubanCore(msg.sender, 0x83c8c0B395850bA55c830451Cfaca4F2A667a983, bytes32(0));

        emit log_address(address(lubanCore));
        LubanEscrow lubanEscrow = new LubanEscrow(address(lubanCore));
        emit log_address(address(lubanEscrow));

        ProposerRegistry lubanProposerRegistry = new ProposerRegistry();
        emit log_address(address(lubanProposerRegistry));

        vm.stopBroadcast();
    }
}
