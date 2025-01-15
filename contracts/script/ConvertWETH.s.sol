// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { WETH9 } from "./WETH.sol";
import { Script } from "forge-std/Script.sol";
import { Test, console } from "forge-std/Test.sol";

contract ConvertWETH is Script, Test {
    function run() public {
        vm.startBroadcast();
        address payable wethAddress = payable(vm.envAddress("WETH_ADDRESS"));
        uint256 amount = vm.envUint("AMOUNT");
        WETH9 weth = WETH9(wethAddress);
        vm.deal(wethAddress, amount);
        weth.deposit{ value: amount }();

        vm.stopBroadcast();
    }
}
