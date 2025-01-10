// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/TaiyiCore.sol";

import { EigenLayerMiddleware } from "../src/EigenLayerMiddleware.sol";
import "../src/TaiyiEscrow.sol";
import { TaiyiProposerRegistry } from "../src/TaiyiProposerRegistry.sol";
import "../src/interfaces/ITaiyiCore.sol";
import "forge-std/Script.sol";
import "forge-std/Test.sol";

import { Reverter } from "./Reverter.sol";
import { WETH9 } from "./WETH.sol";

import { DeployFromScratch } from
    "../lib/eigenlayer-contracts/script/deploy/local/Deploy_From_Scratch.s.sol";

contract Deploy is Script, Test {
    address public avsDirectory;
    address public delegationManager;
    address public strategyManager;
    address public eigenPodManager;

    function run(string memory configFileName) public {
        bool is_for_dev = vm.envBool("IS_FOR_DEV");
        uint256 genesis_timestamp = vm.envUint("GENESIS_TIMESTAMP");
        console.log("genesis timestamp: ", genesis_timestamp);

        if (is_for_dev) {
            vm.startBroadcast();

            Reverter reverter = new Reverter();
            emit log_address(address(reverter));

            WETH9 weth = new WETH9();
            emit log_address(address(weth));

            vm.stopBroadcast();
            DeployFromScratch deployFromScratch = new DeployFromScratch();
            deployFromScratch.run(configFileName);

            string memory outputFile = string(
                bytes("script/output/devnet/local_from_scratch_deployment_data.json")
            );
            string memory output_data = vm.readFile(outputFile);

            avsDirectory = stdJson.readAddress(output_data, ".addresses.avsDirectory");
            delegationManager =
                stdJson.readAddress(output_data, ".addresses.delegationManager");
            strategyManager =
                stdJson.readAddress(output_data, ".addresses.strategyManager");
            eigenPodManager =
                stdJson.readAddress(output_data, ".addresses.eigenPodManager");
        }
        vm.startBroadcast();

        TaiyiProposerRegistry taiyiProposerRegistry = new TaiyiProposerRegistry();
        taiyiProposerRegistry.initialize(msg.sender);
        emit log_address(address(taiyiProposerRegistry));

        TaiyiCore taiyiCore = new TaiyiCore(msg.sender, genesis_timestamp);
        emit log_address(address(taiyiCore));

        EigenLayerMiddleware eigenLayerMiddleware = new EigenLayerMiddleware();
        emit log_address(address(eigenLayerMiddleware));

        eigenLayerMiddleware.initialize(
            msg.sender,
            address(taiyiProposerRegistry),
            avsDirectory,
            delegationManager,
            strategyManager,
            eigenPodManager
        );
        vm.stopBroadcast();
    }
}
