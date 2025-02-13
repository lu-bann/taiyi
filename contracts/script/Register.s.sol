// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IDelegationManagerTypes } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IDelegationManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { Script } from "forge-std/Script.sol";
import { Test, console } from "forge-std/Test.sol";

contract RegisterOperator is Script, Test {
    function run() public {
        vm.startBroadcast();
        address delegationApprover = vm.envAddress("DELEGATION_APPROVER");

        address payable delegationManagerAddress =
            payable(vm.envAddress("DELEGATION_MANAGER"));
        IDelegationManager delegationManager =
            IDelegationManager(delegationManagerAddress);
        string memory metadataURI = "https://www.luban.wtf";

        uint32 allocationDelay = 0;
        delegationManager.registerAsOperator(
            delegationApprover, allocationDelay, metadataURI
        );

        vm.stopBroadcast();
    }
}
