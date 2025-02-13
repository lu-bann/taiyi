// SPDX-License-Identifier: MIT
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
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script, Test {
    address public avsDirectory;
    address public delegationManager;
    address public strategyManagerAddr;
    address public eigenPodManager;
    address public rewardInitiator;
    address public rewardCoordinator;
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
        } else if (
            keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("holesky"))
        ) {
            // holesky address reference: https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/script/configs/holesky.json
            avsDirectory = 0x055733000064333CaDDbC92763c58BF0192fFeBf;
            delegationManager = 0xA44151489861Fe9e3055d95adC98FbD462B948e7;
            strategyManagerAddr = 0xdfB5f6CE42aAA7830E94ECFCcAd411beF4d4D5b6;
            eigenPodManager = 0x30770d7E3e71112d7A6b7259542D1f680a70e315;
            rewardCoordinator = 0xAcc1fb458a1317E886dB376Fc8141540537E68fE;
        }
        rewardInitiator = address(0xd8F3183DEf51a987222d845Be228E0bBB932c292); // Arbitrary address
        vm.startBroadcast();

        // Deploy TaiyiProposerRegistry implementation and proxy
        TaiyiProposerRegistry registryImpl = new TaiyiProposerRegistry();
        bytes memory registryInitData =
            abi.encodeWithSignature("initialize(address)", msg.sender);
        ERC1967Proxy registryProxy =
            new ERC1967Proxy(address(registryImpl), registryInitData);
        TaiyiProposerRegistry registry = TaiyiProposerRegistry(address(registryProxy));
        emit log_address(address(registry));
        vm.serializeAddress(
            "taiyiAddresses", "taiyiProposerRegistryImpl", address(registryImpl)
        );
        vm.serializeAddress(
            "taiyiAddresses", "taiyiProposerRegistryProxy", address(registryProxy)
        );

        // Deploy GatewayAVS implementation and proxy
        GatewayAVS gatewayImpl = new GatewayAVS();
        bytes memory gatewayInitData = abi.encodeWithSignature(
            "initialize(address,address,address,address,address,address,address,address,uint256)",
            msg.sender,
            address(registry),
            avsDirectory,
            delegationManager,
            strategyManagerAddr,
            eigenPodManager,
            rewardCoordinator,
            rewardInitiator,
            8000
        );
        ERC1967Proxy gatewayProxy =
            new ERC1967Proxy(address(gatewayImpl), gatewayInitData);
        GatewayAVS gateway = GatewayAVS(address(gatewayProxy));
        emit log_address(address(gateway));
        vm.serializeAddress("taiyiAddresses", "gatewayAVSImpl", address(gatewayImpl));
        vm.serializeAddress("taiyiAddresses", "gatewayAVSProxy", address(gatewayProxy));

        // Deploy ValidatorAVS implementation and proxy
        ValidatorAVS validatorImpl = new ValidatorAVS();
        bytes memory validatorInitData = abi.encodeWithSignature(
            "initialize(address,address,address,address,address,address,address,address,uint256)",
            msg.sender,
            address(registry),
            avsDirectory,
            delegationManager,
            strategyManagerAddr,
            eigenPodManager,
            rewardCoordinator,
            rewardInitiator,
            8000
        );
        ERC1967Proxy validatorProxy =
            new ERC1967Proxy(address(validatorImpl), validatorInitData);
        ValidatorAVS validator = ValidatorAVS(address(validatorProxy));
        emit log_address(address(validator));
        vm.serializeAddress("taiyiAddresses", "validatorAVSImpl", address(validatorImpl));
        vm.serializeAddress(
            "taiyiAddresses", "validatorAVSProxy", address(validatorProxy)
        );

        // Set AVS contracts in registry
        registry.setAVSContracts(address(gateway), address(validator));

        // Add middleware contracts
        registry.addRestakingMiddlewareContract(address(validator));
        registry.addRestakingMiddlewareContract(address(gateway));

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
            "taiyiAddresses", "eigenLayerMiddleware", address(validator)
        );

        string memory output = "output";
        string memory finalJ = vm.serializeString(output, "taiyiAddresses", addresses);
        vm.writeJson(finalJ, "script/output/devnet/taiyiAddresses.json");

        vm.stopBroadcast();
    }
}
