// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Script, console } from "forge-std/Script.sol";

import { EigenLayerMiddleware } from "../src/eigenlayer-avs/EigenLayerMiddleware.sol";

contract RegisterAVS is Script {
    function run() public {
        address admin = msg.sender;
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/deployments/holesky-taiyiAddresses.json")
        );

        address gatewayAVSAddress = vm.parseJsonAddress(json, "gatewayAVSImpl");
        address validatorAVSAddress = vm.parseJsonAddress(json, "validatorAVSImpl");

        EigenLayerMiddleware gatewayAVS = EigenLayerMiddleware(gatewayAVSAddress);
        EigenLayerMiddleware validatorAVS = EigenLayerMiddleware(validatorAVSAddress);

        string memory gatewayAVSURI = "https://luban.wtf/gatewayAVS.json";
        string memory validatorAVSURI = "https://luban.wtf/validatorAVS.json";

        vm.startBroadcast(admin);
        gatewayAVS.updateAVSMetadataURI(gatewayAVSURI);
        validatorAVS.updateAVSMetadataURI(validatorAVSURI);
        vm.stopBroadcast();
    }
}
