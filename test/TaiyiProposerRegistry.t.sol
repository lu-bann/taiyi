// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Test } from "forge-std/Test.sol";
import { TaiyiProposerRegistry } from "../contracts/src/TaiyiProposerRegistry.sol";
import { ValidatorAVS } from "../contracts/src/eigenlayer-avs/ValidatorAVS.sol";
import { GatewayAVS } from "../contracts/src/eigenlayer-avs/GatewayAVS.sol";
import { IProposerRegistry } from "../contracts/src/interfaces/IProposerRegistry.sol";

contract TaiyiProposerRegistryTest is Test {
    TaiyiProposerRegistry public registry;
    ValidatorAVS public validatorAVS;
    GatewayAVS public gatewayAVS;

    address public owner;
    address public operator;
    address public validator;
    address public rewardsInitiator;
    bytes public operatorBLSPubKey;

    function setUp() public {
        owner = makeAddr("owner");
        operator = makeAddr("operator");
        validator = makeAddr("validator");
        rewardsInitiator = makeAddr("rewardsInitiator");

        // Deploy contracts
        registry = new TaiyiProposerRegistry();
        validatorAVS = new ValidatorAVS();
        gatewayAVS = new GatewayAVS();

        vm.startPrank(owner);

        // Initialize registry first
        registry.initialize(owner);

        // Add middleware contracts
        registry.addRestakingMiddlewareContract(address(validatorAVS));
        registry.addRestakingMiddlewareContract(address(gatewayAVS));

        // Set AVS types
        registry.setAVSType(address(validatorAVS), IProposerRegistry.AVSType.VALIDATOR);
        registry.setAVSType(address(gatewayAVS), IProposerRegistry.AVSType.GATEWAY);

        vm.stopPrank();

        // Create mock BLS key
        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }
    }
} 