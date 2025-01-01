// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/TaiyiCore.sol";

import "../src/TaiyiEscrow.sol";
import { TaiyiProposerRegistry } from "../src/TaiyiProposerRegistry.sol";
import "../src/interfaces/ITaiyiCore.sol";

import { Reverter } from "./Reverter.sol";
import { Script } from "forge-std/Script.sol";
import { Test, console } from "forge-std/Test.sol";

contract Deploy is Script, Test {
    function run() public {
        vm.startBroadcast();

        uint256 genesis_timestamp = vm.envUint("GENESIS_TIMESTAMP");
        console.log("genesis timestamp: ", genesis_timestamp);

        TaiyiProposerRegistry taiyiProposerRegistry = new TaiyiProposerRegistry();
        emit log_address(address(taiyiProposerRegistry));

        TaiyiCore taiyiCore =
            new TaiyiCore(msg.sender, genesis_timestamp, address(taiyiProposerRegistry));
        emit log_address(address(taiyiCore));

        bool is_for_dev = vm.envBool("IS_FOR_DEV");
        if (is_for_dev) {
            Reverter reverter = new Reverter();
            emit log_address(address(reverter));
        }
        vm.stopBroadcast();
    }
}
