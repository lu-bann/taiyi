// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { IDelegationManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { Script } from "forge-std/Script.sol";
import { Test, console } from "forge-std/Test.sol";

contract Register is Script, Test {
    function run() public {
        vm.startBroadcast();
        address delegationApprover = vm.envAddress("DELEGATION_APPROVER");

        IDelegationManager.OperatorDetails memory detail = IDelegationManager
            .OperatorDetails({
            __deprecated_earningsReceiver: msg.sender,
            delegationApprover: delegationApprover,
            stakerOptOutWindowBlocks: 0
        });
        address payable delegationManagerAddress =
            payable(vm.envAddress("DELEGATION_MANAGER"));
        IDelegationManager delegationManager =
            IDelegationManager(delegationManagerAddress);
        string memory metadataURI = "https://www.luban.wtf";
        delegationManager.registerAsOperator(detail, metadataURI);

        vm.stopBroadcast();
    }
}
