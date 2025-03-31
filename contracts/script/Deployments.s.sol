// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/TaiyiCore.sol";

import "forge-std/Script.sol";
import "forge-std/Test.sol";

import { EigenLayerMiddleware } from "../src/eigenlayer-avs/EigenLayerMiddleware.sol";
import { TaiyiRegistryCoordinator } from
    "../src/operator-registries/TaiyiRegistryCoordinator.sol";
import { Reverter } from "./Reverter.sol";
import { WETH9 } from "./WETH.sol";

import { DeployFromScratch } from
    "../lib/eigenlayer-contracts/script/deploy/local/Deploy_From_Scratch.s.sol";

import { IAllocationManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { IStrategy } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IStrategyManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script, Test {
    address public avsDirectory;
    address public delegationManager;
    address public strategyManagerAddr;
    address public eigenPodManager;
    address public rewardInitiator;
    address public rewardCoordinator;
    address public allocationManager;
    address public eigenPauserReg;
    address public deployer;

    function run(string memory configFileName) public {
        // Get deployer address from private key
        string memory pkString = vm.envString("PRIVATE_KEY");
        // Check if pkString starts with "0x"; if not, add the prefix.
        bytes memory pkBytes = bytes(pkString);
        if (pkBytes.length < 2 || pkBytes[0] != 0x30 || pkBytes[1] != 0x78) {
            pkString = string.concat("0x", pkString);
        }
        uint256 deployerPrivateKey = vm.parseUint(pkString); // Parse as hex
        deployer = vm.addr(deployerPrivateKey);

        string memory network = vm.envString("NETWORK");

        string memory taiyiAddresses = "taiyiAddresses";

        vm.createDir("script/output/devnet", true);

        if (keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("devnet")))
        {
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

            string memory outputFile =
                string(bytes("script/output/devnet/M2_from_scratch_deployment_data.json"));
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
            rewardCoordinator =
                stdJson.readAddress(output_data, ".addresses.rewardsCoordinator");
            allocationManager =
                stdJson.readAddress(output_data, ".addresses.allocationManager");
            eigenPauserReg =
                stdJson.readAddress(output_data, ".addresses.eigenLayerPauserReg");
        } else if (
            keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("holesky"))
        ) {
            // holesky address reference: https://github.com/Layr-Labs/eigenlayer-contracts/tree/testnet-holesky
            avsDirectory = 0x055733000064333CaDDbC92763c58BF0192fFeBf;
            delegationManager = 0xA44151489861Fe9e3055d95adC98FbD462B948e7;
            strategyManagerAddr = 0xdfB5f6CE42aAA7830E94ECFCcAd411beF4d4D5b6;
            eigenPodManager = 0x30770d7E3e71112d7A6b7259542D1f680a70e315;
            rewardCoordinator = 0xAcc1fb458a1317E886dB376Fc8141540537E68fE;
            allocationManager = 0x78469728304326CBc65f8f95FA756B0B73164462;
        }
        rewardInitiator = address(0xd8F3183DEf51a987222d845Be228E0bBB932c292); // Arbitrary address
        vm.startBroadcast();

        // Deploy TaiyiRegistryCoordinator implementation and proxy
        TaiyiRegistryCoordinator registryImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(allocationManager),
            IPauserRegistry(eigenPauserReg),
            "TaiyiRegistryCoordinator"
        );
        bytes memory registryInitData =
            abi.encodeWithSignature("initialize(address)", msg.sender);
        ERC1967Proxy registryProxy =
            new ERC1967Proxy(address(registryImpl), registryInitData);
        TaiyiRegistryCoordinator registry =
            TaiyiRegistryCoordinator(address(registryProxy));
        emit log_address(address(registry));
        vm.serializeAddress(
            "taiyiAddresses", "taiyiRegistryCoordinatorImpl", address(registryImpl)
        );
        vm.serializeAddress(
            "taiyiAddresses", "taiyiRegistryCoordinatorProxy", address(registryProxy)
        );

        EigenLayerMiddleware eigenLayerMiddlewareImpl = new EigenLayerMiddleware();
        bytes memory eigenLayerMiddlewareInitData = abi.encodeWithSignature(
            "initialize(address,address,address,address,address,address,address,address,uint256)",
            msg.sender,
            avsDirectory,
            delegationManager,
            strategyManagerAddr,
            eigenPodManager,
            rewardCoordinator,
            rewardInitiator,
            8000,
            address(registry)
        );
        ERC1967Proxy eigenLayerMiddlewareProxy = new ERC1967Proxy(
            address(eigenLayerMiddlewareImpl), eigenLayerMiddlewareInitData
        );
        EigenLayerMiddleware eigenLayerMiddleware =
            EigenLayerMiddleware(address(eigenLayerMiddlewareProxy));
        emit log_address(address(eigenLayerMiddleware));
        vm.serializeAddress(
            "taiyiAddresses",
            "eigenLayerMiddlewareImpl",
            address(eigenLayerMiddlewareImpl)
        );
        vm.serializeAddress(
            "taiyiAddresses",
            "eigenLayerMiddlewareProxy",
            address(eigenLayerMiddlewareProxy)
        );

        // Deploy TaiyiCore implementation and proxy
        TaiyiCore coreImpl = new TaiyiCore();
        bytes memory coreInitData =
            abi.encodeWithSignature("initialize(address)", msg.sender);
        ERC1967Proxy coreProxy = new ERC1967Proxy(address(coreImpl), coreInitData);
        TaiyiCore core = TaiyiCore(payable(address(coreProxy)));
        emit log_address(address(core));
        vm.serializeAddress("taiyiAddresses", "taiyiCoreImpl", address(coreImpl));
        vm.serializeAddress("taiyiAddresses", "taiyiCoreProxy", address(coreProxy));

        string memory addresses = vm.serializeAddress(
            "taiyiAddresses", "eigenLayerMiddleware", address(eigenLayerMiddleware)
        );

        string memory output = "output";
        string memory finalJ = vm.serializeString(output, "taiyiAddresses", addresses);
        vm.writeJson(finalJ, "script/output/devnet/taiyiAddresses.json");

        vm.stopBroadcast();
    }
}
