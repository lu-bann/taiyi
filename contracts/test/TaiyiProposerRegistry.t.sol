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

        // Add a restaking contract
        vm.prank(owner);
        registry.addRestakingMiddlewareContract(middleware);
    }

    function test_Initialization() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.gatewayAVSAddress(), address(0));
        assertEq(registry.validatorAVSAddress(), address(0));
    }

    /// @notice Test middleware management functions
    function test_MiddlewareManagement() public {
        address newMiddleware = makeAddr("newMiddleware");

        vm.startPrank(owner);
        registry.addRestakingMiddlewareContract(newMiddleware);
        registry.removeRestakingMiddlewareContract(newMiddleware);
        vm.stopPrank();

        vm.expectRevert("Unauthorized middleware");
        vm.prank(newMiddleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);
    }

    /// @notice Test Gateway operator registration
    function test_GatewayOperatorRegistration() public {
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);

        IProposerRegistry.Operator memory op = registry.getRegisteredOperator(operator);
        assertEq(op.operatorAddress, operator);
        assertEq(uint256(op.avsType), uint256(IProposerRegistry.AVSType.GATEWAY));
        assertEq(keccak256(op.blsKey), keccak256(mockBlsKey));
        assertTrue(registry.isOperatorRegisteredInGatewayAVS(operator));
    }

    /// @notice Test Validator operator registration
    function test_ValidatorOperatorRegistration() public {
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        IProposerRegistry.Operator memory op = registry.getRegisteredOperator(operator);
        assertEq(op.operatorAddress, operator);
        assertEq(uint256(op.avsType), uint256(IProposerRegistry.AVSType.VALIDATOR));
        assertEq(op.blsKey.length, 0);
        assertTrue(registry.isOperatorRegisteredInValidatorAVS(operator));
    }

    /// @notice Test validator registration with delegatee
    function test_ValidatorRegistrationWithDelegatee() public {
        // Register operator first
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        // Create validator data
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

    /// @notice Test batch validator registration
    function test_BatchValidatorRegistration() public {
        // Register operator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        // Create multiple validator data
        bytes[] memory pubkeys = new bytes[](2);
        bytes[] memory delegatees = new bytes[](2);

        for (uint256 j = 0; j < 2; j++) {
            pubkeys[j] = new bytes(48);
            delegatees[j] = new bytes(48);
            for (uint256 i = 0; i < 48; i++) {
                pubkeys[j][i] = bytes1(uint8(0xcd + j));
                delegatees[j][i] = bytes1(uint8(0xef + j));
            }
        }

        // Batch register
        vm.prank(middleware);
        registry.batchRegisterValidators(pubkeys, operator, delegatees);

        // Verify all registrations
        for (uint256 i = 0; i < pubkeys.length; i++) {
            bytes32 pubkeyHash = keccak256(pubkeys[i]);
            IProposerRegistry.Validator memory validator =
                registry.getValidator(pubkeyHash);

            assertEq(validator.operator, operator);
            assertEq(keccak256(validator.pubkey), keccak256(pubkeys[i]));
            assertEq(keccak256(validator.delegatee), keccak256(delegatees[i]));
            assertEq(
                uint8(validator.status), uint8(IProposerRegistry.ValidatorStatus.Active)
            );
        }
    }

    /// @notice Test validator opt-out process
    function test_ValidatorOptOut() public {
        // Setup validator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(middleware);
        registry.registerValidator(validatorPubkey, operator, delegatee);

        bytes32 pubkeyHash = keccak256(validatorPubkey);

        // Init opt-out
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        assertEq(
            uint8(registry.getValidatorStatus(pubkeyHash)),
            uint8(IProposerRegistry.ValidatorStatus.OptingOut)
        );

        // Wait cooldown
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);

        // Confirm opt-out
        registry.confirmOptOut(pubkeyHash);
        assertEq(
            uint8(registry.getValidatorStatus(pubkeyHash)),
            uint8(IProposerRegistry.ValidatorStatus.OptedOut)
        );
    }

    /// @notice Test AVS type management
    function test_AVSTypeManagement() public {
        address avs = makeAddr("avs");

        vm.prank(owner);
        registry.setAVSType(avs, IProposerRegistry.AVSType.GATEWAY);
        assertEq(
            uint8(registry.getAVSType(avs)), uint8(IProposerRegistry.AVSType.GATEWAY)
        );

        vm.prank(owner);
        registry.setAVSType(avs, IProposerRegistry.AVSType.VALIDATOR);
        assertEq(
            uint8(registry.getAVSType(avs)), uint8(IProposerRegistry.AVSType.VALIDATOR)
        );
    }

    /// @notice Test operator counting and querying
    function test_OperatorQueries() public {
        // Register operators
        vm.startPrank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);
        registry.registerOperator(operator2, IProposerRegistry.AVSType.VALIDATOR, "");
        vm.stopPrank();

        // Test operator queries
        address[] memory gatewayOps = registry.getActiveOperatorsForAVS(
            registry.gatewayAVSAddress(), IProposerRegistry.AVSType.GATEWAY
        );
        assertEq(gatewayOps.length, 1);
        assertEq(gatewayOps[0], operator);

        address[] memory validatorOps = registry.getActiveOperatorsForAVS(
            registry.validatorAVSAddress(), IProposerRegistry.AVSType.VALIDATOR
        );
        assertEq(validatorOps.length, 1);
        assertEq(validatorOps[0], operator2);
    }

    function test_RegisterOperatorRevertsIfAlreadyRegistered() public {
        // First time success
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);

        // Second time revert
        vm.prank(middleware);
        vm.expectRevert(bytes("Operator already registered"));
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);
    }

    function test_RegisterOperatorRevertsIfNotCalledByMiddleware() public {
        vm.expectRevert(bytes("Unauthorized middleware"));
        registry.registerOperator(operator, IProposerRegistry.AVSType.GATEWAY, mockBlsKey);
    }

    /// @notice Test operator deregistration with active validators
    function test_DeregisterOperatorRevertsWithActiveValidators() public {
        // Setup operator and validator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(middleware);
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Attempt to deregister with active validator should fail
        vm.prank(middleware);
        vm.expectRevert(TaiyiProposerRegistry.CannotDeregisterActiveValidator.selector);
        registry.deregisterOperator(operator);
    }

    /// @notice Test operator deregistration with validators in cooldown
    function test_DeregisterOperatorRevertsInCooldown() public {
        // Setup operator and validator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(middleware);
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Initiate opt-out
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);

        // Attempt to deregister during cooldown should fail
        vm.prank(middleware);
        vm.expectRevert(TaiyiProposerRegistry.CannotDeregisterInCooldown.selector);
        registry.deregisterOperator(operator);
    }

    /// @notice Test successful operator deregistration after validator opt-out
    function test_SuccessfulDeregistrationAfterOptOut() public {
        // Setup operator and validator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(middleware);
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Complete opt-out process
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);
        registry.confirmOptOut(pubkeyHash);

        // Verify events are emitted correctly
        vm.expectEmit(true, true, false, true);
        emit TaiyiProposerRegistry.OperatorDeregistered(operator, middleware);

        vm.expectEmit(true, false, false, true);
        bytes[] memory expectedPubkeys = new bytes[](1);
        expectedPubkeys[0] = validatorPubkey;
        emit TaiyiProposerRegistry.ValidatorsOptedOut(operator, expectedPubkeys);

        // Deregister operator
        vm.prank(middleware);
        registry.deregisterOperator(operator);

        // Verify operator is fully deregistered
        assertFalse(registry.isOperatorRegisteredInGatewayAVS(operator));
        assertFalse(registry.isOperatorRegisteredInValidatorAVS(operator));
        assertFalse(registry.isOperatorActiveInAVS(middleware, operator));

        // Verify operator data is cleared
        IProposerRegistry.Operator memory opData =
            registry.getRegisteredOperator(operator);
        assertEq(opData.operatorAddress, address(0));
        assertEq(opData.restakingMiddlewareContract, address(0));
        assertEq(opData.blsKey.length, 0);
    }

    /// @notice Test post-deregistration restrictions
    function test_PostDeregistrationRestrictions() public {
        // Setup and deregister operator with opted out validator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(middleware);
        registry.registerValidator(validatorPubkey, operator, delegatee);

        bytes32 pubkeyHash = keccak256(validatorPubkey);
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);
        registry.confirmOptOut(pubkeyHash);

        vm.prank(middleware);
        registry.deregisterOperator(operator);

        // Attempt post-deregistration actions
        vm.startPrank(middleware);

        // Should not be able to register new validators
        bytes memory newValidatorPubkey = new bytes(48);
        vm.expectRevert("Operator not registered");
        registry.registerValidator(newValidatorPubkey, operator, delegatee);

        // Should not be able to register as operator again without clearing previous state
        vm.expectRevert("Operator already registered");
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        // Verify validator count is zero
        assertEq(registry.getValidatorCountForOperatorInAVS(middleware, operator), 0);
        vm.stopPrank();
    }

    /// @notice Test deregistration with multiple validators
    function test_DeregistrationWithMultipleValidators() public {
        // Setup operator
        vm.prank(middleware);
        registry.registerOperator(operator, IProposerRegistry.AVSType.VALIDATOR, "");

        // Register multiple validators
        uint256 validatorCount = 3;
        bytes[] memory pubkeys = new bytes[](validatorCount);
        bytes[] memory delegatees = new bytes[](validatorCount);
        bytes32[] memory pubkeyHashes = new bytes32[](validatorCount);

        for (uint256 i = 0; i < validatorCount; i++) {
            pubkeys[i] = new bytes(48);
            delegatees[i] = new bytes(48);
            for (uint256 j = 0; j < 48; j++) {
                pubkeys[i][j] = bytes1(uint8(0xcd + i));
                delegatees[i][j] = bytes1(uint8(0xef + i));
            }
            pubkeyHashes[i] = keccak256(pubkeys[i]);

            vm.prank(middleware);
            registry.registerValidator(pubkeys[i], operator, delegatees[i]);
        }

        // Opt out all validators
        for (uint256 i = 0; i < validatorCount; i++) {
            registry.initOptOut(pubkeyHashes[i], block.timestamp + 1 days);
        }

        // Wait cooldown and confirm opt-out for all
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);
        for (uint256 i = 0; i < validatorCount; i++) {
            registry.confirmOptOut(pubkeyHashes[i]);
        }

        // Verify events for multiple validators
        vm.expectEmit(true, true, false, true);
        emit TaiyiProposerRegistry.OperatorDeregistered(operator, middleware);

        vm.expectEmit(true, false, false, true);
        emit TaiyiProposerRegistry.ValidatorsOptedOut(operator, pubkeys);

        // Deregister operator
        vm.prank(middleware);
        registry.deregisterOperator(operator);

        // Verify all validators are properly cleared
        for (uint256 i = 0; i < validatorCount; i++) {
            IProposerRegistry.Validator memory validator =
                registry.getValidator(pubkeyHashes[i]);
            assertEq(
                uint8(validator.status), uint8(IProposerRegistry.ValidatorStatus.OptedOut)
            );
        }
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
