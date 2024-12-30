// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/TaiyiProposerRegistry.sol";
import "../src/interfaces/IProposerRegistry.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract TaiyiProposerRegistryTest is Test {
    TaiyiProposerRegistry public registry;

    address owner = makeAddr("owner");
    address middleware = makeAddr("middleware");
    address operator = makeAddr("operator");
    address operator2 = makeAddr("operator2");

    function setUp() public {
        // Deploy the registry
        registry = new TaiyiProposerRegistry();
        registry.initialize(owner);

        // Verify operators aren't registered after initialization
        assertFalse(registry.isOperatorRegistered(operator));
        assertFalse(registry.isOperatorRegistered(operator2));

        // Add a restaking contract
        vm.prank(owner);
        registry.addRestakingMiddlewareContract(middleware);
    }

    function testInitialization() public {
        assertEq(registry.owner(), owner);
    }

    function testRegisterOperator() public {
        // Must be called by the restaking contract
        vm.prank(middleware);
        registry.registerOperator(operator, address(0xdead));

        // Check that it was registered
        (address opAddr, address restakingContract) = getOperatorData(operator);
        assertEq(opAddr, operator);
        assertEq(restakingContract, address(0xdead));

        bool isReg = registry.isOperatorRegistered(operator);
        assertTrue(isReg);
    }

    function testRegisterOperatorRevertsIfAlreadyRegistered() public {
        // First time success
        vm.prank(middleware);
        registry.registerOperator(operator, address(0xdead));

        // Second time revert
        vm.prank(middleware);
        vm.expectRevert(bytes("Operator already registered"));
        registry.registerOperator(operator, address(0xdead));
    }

    function testRegisterOperatorRevertsIfNotCalledByMiddleware() public {
        vm.expectRevert(bytes("Unauthorized middleware"));
        registry.registerOperator(operator, address(0xdead));
    }

    function testDeregisterOperator() public {
        // Register
        vm.prank(middleware);
        registry.registerOperator(operator2, address(0xbeef));

        // Deregister
        vm.prank(middleware);
        registry.deregisterOperator(operator2);

        bool isReg = registry.isOperatorRegistered(operator2);
        assertFalse(isReg);

        // Confirm operator record is reset
        (address opAddr, address restakingContract) = getOperatorData(operator2);
        assertEq(opAddr, address(0));
        assertEq(restakingContract, address(0));
    }

    function testDeregisterOperatorRevertIfNotRegistered() public {
        vm.prank(middleware);
        vm.expectRevert(bytes("Operator not registered"));
        registry.deregisterOperator(operator2);
    }

    function testIsOperatorRegisteredFalseWhenNotRegistered() public {
        bool isReg = registry.isOperatorRegistered(operator2);
        assertFalse(isReg);
    }

    // Helper function to read the Operator struct
    function getOperatorData(address operatorAddr)
        internal
        view
        returns (address opAddress, address restakingContract)
    {
        (opAddress, restakingContract) = registry.registeredOperators(operatorAddr);
    }
}
