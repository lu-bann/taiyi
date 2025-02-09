// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/TaiyiCore.sol";

import { GatewayAVS } from "../src/eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "../src/eigenlayer-avs/ValidatorAVS.sol";

import "../src/TaiyiEscrow.sol";
import { TaiyiProposerRegistry } from "../src/TaiyiProposerRegistry.sol";
import { EigenLayerMiddleware } from "../src/abstract/EigenLayerMiddleware.sol";
import "../src/interfaces/ITaiyiCore.sol";
import "forge-std/Script.sol";
import "forge-std/Test.sol";

import { Reverter } from "./Reverter.sol";
import { WETH9 } from "./WETH.sol";

import { DeployFromScratch } from
    "../lib/eigenlayer-contracts/script/deploy/local/Deploy_From_Scratch.s.sol";
import { IStrategy } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IStrategyManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";

contract Deploy is Script, Test {
    address public avsDirectory;
    address public delegationManager;
    address public strategyManagerAddr;
    address public eigenPodManager;
    address public rewardInitiator;
    address public rewardCoordinator;

    function run(string memory configFileName) public {
        bool is_for_dev = vm.envBool("IS_FOR_DEV");
        uint256 genesis_timestamp = vm.envUint("GENESIS_TIMESTAMP");
        console.log("genesis timestamp: ", genesis_timestamp);

        string memory taiyiAddresses = "taiyiAddresses";

        if (is_for_dev) {
            vm.startBroadcast();

            Reverter reverter = new Reverter();
            emit log_address(address(reverter));
            vm.serializeAddress(taiyiAddresses, "reverter", address(reverter));

            WETH9 weth = new WETH9();
            emit log_address(address(weth));
            vm.serializeAddress(taiyiAddresses, "weth", address(weth));
            vm.stopBroadcast();
            DeployFromScratch deployFromScratch = new DeployFromScratch();
            deployFromScratch.run(configFileName);

            string memory outputFile = string(
                bytes("script/output/devnet/local_from_scratch_deployment_data.json")
            );
            string memory output_data = vm.readFile(outputFile);

            // whitelist weth
            address strategyWethAddr =
                stdJson.readAddress(output_data, ".addresses.strategies.WETH");
            strategyManagerAddr =
                stdJson.readAddress(output_data, ".addresses.strategyManager");
            IStrategy strategyWeth = IStrategy(strategyWethAddr);
            IStrategy[] memory strategiesToWhitelist = new IStrategy[](1);
            bool[] memory thirdPartyTransfersForbiddenValues = new bool[](1);
            strategiesToWhitelist[0] = strategyWeth;
            thirdPartyTransfersForbiddenValues[0] = true;
            IStrategyManager strategyManager = IStrategyManager(strategyManagerAddr);
            vm.startBroadcast();
            strategyManager.addStrategiesToDepositWhitelist(strategiesToWhitelist);
            vm.stopBroadcast();

            avsDirectory = stdJson.readAddress(output_data, ".addresses.avsDirectory");
            delegationManager =
                stdJson.readAddress(output_data, ".addresses.delegationManager");
            strategyManagerAddr =
                stdJson.readAddress(output_data, ".addresses.strategyManager");
            eigenPodManager =
                stdJson.readAddress(output_data, ".addresses.eigenPodManager");

            // Todo: Remove arbitrary addresses and update them with the correct ones in DeployFromScratch.s.sol
            rewardInitiator = address(0xd8F3183DEf51a987222d845Be228E0bBB932c292); // Arbitrary address
            rewardCoordinator = address(0x1234567890123456789012345678901234567890); // Arbitrary address
        }
        vm.startBroadcast();

        // Deploy AVS contracts first
        GatewayAVS gatewayAVS = new GatewayAVS();
        ValidatorAVS validatorAVS = new ValidatorAVS();

        // Deploy registry
        TaiyiProposerRegistry taiyiProposerRegistry = new TaiyiProposerRegistry();
        taiyiProposerRegistry.initialize(msg.sender);

        // Initialize AVS contracts
        gatewayAVS.initialize(
            msg.sender,
            address(taiyiProposerRegistry),
            avsDirectory,
            delegationManager,
            strategyManagerAddr,
            eigenPodManager,
            rewardCoordinator,
            rewardInitiator,
            8000 // 80% to gateway
        );

        validatorAVS.initialize(
            msg.sender,
            address(taiyiProposerRegistry),
            avsDirectory,
            delegationManager,
            strategyManagerAddr,
            eigenPodManager,
            rewardCoordinator,
            rewardInitiator,
            8000 // 80% to gateway
        );

        // Set AVS contracts in registry
        taiyiProposerRegistry.setAVSContracts(address(gatewayAVS), address(validatorAVS));

        // Add middleware contracts
        taiyiProposerRegistry.addRestakingMiddlewareContract(address(validatorAVS));

        emit log_address(address(taiyiProposerRegistry));
        vm.serializeAddress(
            taiyiAddresses, "taiyiProposerRegistry", address(taiyiProposerRegistry)
        );

        emit log_address(address(gatewayAVS));
        vm.serializeAddress(taiyiAddresses, "gatewayAVS", address(gatewayAVS));

        emit log_address(address(validatorAVS));
        vm.serializeAddress(taiyiAddresses, "validatorAVS", address(validatorAVS));

        TaiyiCore taiyiCore = new TaiyiCore();
        taiyiCore.initialize(msg.sender);
        emit log_address(address(taiyiCore));
        vm.serializeAddress(taiyiAddresses, "taiyiCore", address(taiyiCore));

        string memory addresses = vm.serializeAddress(
            taiyiAddresses, "eigenLayerMiddleware", address(validatorAVS)
        );

        string memory output = "output";
        string memory finalJ = vm.serializeString(output, taiyiAddresses, addresses);
        vm.writeJson(finalJ, "script/output/devnet/taiyiAddresses.json");
        vm.stopBroadcast();
    }
}
