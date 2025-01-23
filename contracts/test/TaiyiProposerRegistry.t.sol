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
    bytes mockBlsKey;

    function setUp() public {
        // Deploy the registry
        registry = new TaiyiProposerRegistry();
        registry.initialize(owner);

        // Create mock BLS key
        mockBlsKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            mockBlsKey[i] = 0xab;
        }

        // Verify operators aren't registered after initialization
        // assertFalse(registry.isOperatorRegistered(operator));
        // assertFalse(registry.isOperatorRegistered(operator2));

        // Add a restaking contract
        vm.prank(owner);
        registry.addRestakingMiddlewareContract(middleware);
    }

    function testInitialization() public view {
        assertEq(registry.owner(), owner);
    }

    function testRegisterGatewayOperator() public {
        // Must be called by the restaking contract
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);

        // Check that it was registered
        (
            address opAddr,
            address restakingContract,
            IProposerRegistry.AVSType avsType,
            bytes memory blsKey
        ) = getOperatorData(operator);
        assertEq(opAddr, operator);
        assertEq(restakingContract, middleware);
        assertEq(uint8(avsType), uint8(IProposerRegistry.AVSType.GATEWAY));
        assertEq(keccak256(blsKey), keccak256(mockBlsKey));

        bool isReg = registry.isOperatorRegisteredInGatewayAVS(operator);
        assertTrue(isReg);
    }

    function testRegisterValidatorOperator() public {
        // Must be called by the restaking contract
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        // Check that it was registered
        (
            address opAddr,
            address restakingContract,
            IProposerRegistry.AVSType avsType,
            bytes memory blsKey
        ) = getOperatorData(operator);
        assertEq(opAddr, operator);
        assertEq(restakingContract, middleware);
        assertEq(uint8(avsType), uint8(IProposerRegistry.AVSType.VALIDATOR));
        assertEq(blsKey.length, 0);

        bool isReg = registry.isOperatorRegisteredInValidatorAVS(operator);
        assertTrue(isReg);
    }

    function testRegisterOperatorRevertsIfAlreadyRegistered() public {
        // First time success
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);

        // Second time revert
        vm.prank(middleware);
        vm.expectRevert(bytes("Operator already registered"));
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);
    }

    function testRegisterOperatorRevertsIfNotCalledByMiddleware() public {
        vm.expectRevert(bytes("Unauthorized middleware"));
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);
    }

    function testDeregisterOperator() public {
        // Register
        vm.prank(middleware);
        registry.registerOperator(
            operator2, IProposerRegistry.AVSType.GATEWAY, mockBlsKey
        );

        // Deregister
        vm.prank(middleware);
        registry.deregisterOperator(operator2);

        // bool isReg = registry.isOperatorRegistered(operator2);
        // assertFalse(isReg);

        // Confirm operator record is reset
        (
            address opAddr,
            address restakingContract,
            IProposerRegistry.AVSType avsType,
            bytes memory blsKey
        ) = getOperatorData(operator2);
        assertEq(opAddr, address(0));
        assertEq(restakingContract, address(0));
        assertEq(uint8(avsType), uint8(IProposerRegistry.AVSType.GATEWAY)); // Default enum value
        assertEq(blsKey.length, 0);
    }

    function testRegisterValidatorWithDelegatee() public {
        // Register operator first
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        // Create test validator pubkey and delegatee
        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        // Register validator
        vm.prank(middleware);
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Verify registration
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        IProposerRegistry.Validator memory validator = registry.getValidator(pubkeyHash);

        assertEq(validator.operator, operator);
        assertEq(keccak256(validator.pubkey), keccak256(validatorPubkey));
        assertEq(keccak256(validator.delegatee), keccak256(delegatee));
        assertEq(uint8(validator.status), uint8(IProposerRegistry.ValidatorStatus.Active));
    }

    function testRegisterValidatorFailsWithEmptyDelegatee() public {
        // Register operator first
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        bytes memory validatorPubkey = new bytes(48);
        bytes memory emptyDelegatee = "";

        // Should revert when trying to register with empty delegatee
        vm.prank(middleware);
        vm.expectRevert("Invalid delegatee");
        registry.registerValidator(validatorPubkey, operator, emptyDelegatee);
    }

    // Helper function to read the Operator struct
    function getOperatorData(address operatorAddr)
        internal
        view
        returns (
            address opAddress,
            address restakingContract,
            IProposerRegistry.AVSType avsType,
            bytes memory blsKey
        )
    {
        IProposerRegistry.Operator memory op =
            registry.getRegisteredOperator(operatorAddr);
        return (op.operatorAddress, op.restakingMiddlewareContract, op.avsType, op.blsKey);
    }
}
