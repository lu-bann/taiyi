// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/TaiyiProposerRegistry.sol";

import "../src/eigenlayer-avs/UnderwriterAVS.sol";
import "../src/eigenlayer-avs/ValidatorAVS.sol";
import "../src/interfaces/IProposerRegistry.sol";

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";

import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "forge-std/Test.sol";

contract TaiyiProposerRegistryTest is Test {
    TaiyiProposerRegistry public registry;

    uint256 constant UNDERWRITER_SHARE_BIPS = 8000; // 80%

    address public owner;
    address public operator;
    bytes public mockBlsPubKey;
    EigenlayerDeployer public eigenLayerDeployer;
    address public rewardsInitiator;

    function setUp() public {
        owner = makeAddr("owner");
        operator = makeAddr("operator");
        mockBlsPubKey = abi.encodePacked("mockBlsPubKey");
        rewardsInitiator = makeAddr("rewardInitiator");
        address proxyAdmin = makeAddr("proxyAdmin"); // Create separate admin for proxies

        eigenLayerDeployer = new EigenlayerDeployer();
        eigenLayerDeployer.setUp();

        vm.startPrank(owner);

        // Deploy TaiyiProposerRegistry as an upgradeable instance
        TaiyiProposerRegistry registryImpl = new TaiyiProposerRegistry();
        TransparentUpgradeableProxy registryProxy = new TransparentUpgradeableProxy(
            address(registryImpl),
            proxyAdmin, // Use proxyAdmin instead of owner
            abi.encodeWithSelector(TaiyiProposerRegistry.initialize.selector, owner)
        );
        registry = TaiyiProposerRegistry(address(registryProxy));

        // Deploy UnderwriterAVS as an upgradeable proxy
        UnderwriterAVS underwriterImpl = new UnderwriterAVS();
        TransparentUpgradeableProxy underwriterProxy = new TransparentUpgradeableProxy(
            address(underwriterImpl),
            proxyAdmin, // Use proxyAdmin instead of owner
            abi.encodeWithSelector(
                UnderwriterAVS.initialize.selector,
                owner,
                address(registry),
                address(eigenLayerDeployer.avsDirectory()),
                address(eigenLayerDeployer.delegation()),
                address(eigenLayerDeployer.strategyManager()),
                address(eigenLayerDeployer.eigenPodManager()),
                address(eigenLayerDeployer.rewardsCoordinator()),
                rewardsInitiator,
                UNDERWRITER_SHARE_BIPS
            )
        );
        UnderwriterAVS underwriterAVSInstance = UnderwriterAVS(address(underwriterProxy));

        // Deploy ValidatorAVS as an upgradeable proxy
        ValidatorAVS validatorImpl = new ValidatorAVS();
        TransparentUpgradeableProxy validatorProxy = new TransparentUpgradeableProxy(
            address(validatorImpl),
            proxyAdmin, // Use proxyAdmin instead of owner
            abi.encodeWithSelector(
                ValidatorAVS.initialize.selector,
                owner,
                address(registry),
                address(eigenLayerDeployer.avsDirectory()),
                address(eigenLayerDeployer.delegation()),
                address(eigenLayerDeployer.strategyManager()),
                address(eigenLayerDeployer.eigenPodManager()),
                address(eigenLayerDeployer.rewardsCoordinator()),
                rewardsInitiator,
                UNDERWRITER_SHARE_BIPS
            )
        );
        ValidatorAVS validatorAVSInstance = ValidatorAVS(address(validatorProxy));

        // Set AVS contracts in registry
        registry.setAVSContracts(
            address(underwriterAVSInstance), address(validatorAVSInstance)
        );

        // Add middleware contracts
        // registry.addRestakingMiddlewareContract(address(validatorAVSInstance));
        // registry.addRestakingMiddlewareContract(address(underwriterAVSInstance));

        vm.stopPrank();
    }

    function testInitialization() public view {
        assertEq(registry.owner(), owner);
        assertTrue(
            registry.isOperatorRegisteredInAVS(
                address(registry.underwriterAVS()),
                IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            ) == false
        );
        assertTrue(
            registry.isOperatorRegisteredInAVS(
                address(registry.validatorAVS()),
                IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            ) == false
        );
    }

    /// @notice Test EigenLayer Underwriter operator registration
    function test_EigenLayerUnderwriterOperatorRegistration() public {
        vm.prank(address(registry.underwriterAVS()));
        registry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            mockBlsPubKey
        );

        (IProposerRegistry.Operator memory underwriterOp,) =
            registry.getOperatorData(operator);
        assertEq(underwriterOp.operatorAddress, operator);
        assertEq(
            uint256(underwriterOp.serviceType),
            uint256(IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER)
        );
        assertEq(keccak256(underwriterOp.blsKey), keccak256(mockBlsPubKey));
        assertTrue(
            registry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            )
        );
    }

    /// @notice Test EigenLayer Validator operator registration
    function test_EigenLayerValidatorOperatorRegistration() public {
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        (, IProposerRegistry.Operator memory validatorOp) =
            registry.getOperatorData(operator);
        assertEq(validatorOp.operatorAddress, operator);
        assertEq(
            uint256(validatorOp.serviceType),
            uint256(IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR)
        );
        assertEq(validatorOp.blsKey.length, 0);
        assertTrue(
            registry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            )
        );
    }

    /// @notice Test validator registration with delegatee
    function test_ValidatorRegistrationWithDelegatee() public {
        // Register operator first
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        // Create validator data
        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        // Register validator
        vm.prank(address(registry.validatorAVS()));
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Verify registration
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        IProposerRegistry.Validator memory validator = registry.getValidator(pubkeyHash);

        assertEq(validator.operator, operator);
        assertEq(keccak256(validator.pubkey), keccak256(validatorPubkey));
        assertEq(keccak256(validator.delegatee), keccak256(delegatee));
        assertEq(uint8(validator.status), uint8(IProposerRegistry.ValidatorStatus.Active));
        assertTrue(
            registry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            )
        );
    }

    /// @notice Test batch validator registration
    function test_BatchValidatorRegistration() public {
        // Register operator
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

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

        // Verify operator is registered before batch registration
        assertTrue(
            registry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            ),
            "Operator should be registered"
        );

        // Batch register
        vm.prank(address(registry.validatorAVS()));
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
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(address(registry.validatorAVS()));
        registry.registerValidator(validatorPubkey, operator, delegatee);

        bytes32 pubkeyHash = keccak256(validatorPubkey);

        // Init opt-out
        vm.startPrank(address(registry.validatorAVS()), operator);
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        vm.stopPrank();
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
        address underwriterAVS = makeAddr("underwriterAVS");
        address validatorAVS = makeAddr("validatorAVS");

        vm.prank(owner);
        registry.setAVSContracts(underwriterAVS, validatorAVS);
        assertEq(
            uint8(registry.getAvsType(underwriterAVS)),
            uint8(IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER)
        );

        assertEq(
            uint8(registry.getAvsType(validatorAVS)),
            uint8(IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR)
        );
    }

    /// @notice Test operator counting and querying
    function test_OperatorQueries() public {
        // Register operator in Underwriter AVS
        vm.startPrank(address(registry.underwriterAVS()));
        registry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            mockBlsPubKey
        );
        vm.stopPrank();

        // Register operator in Validator AVS
        vm.startPrank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );
        vm.stopPrank();

        // Test Underwriter operator queries
        address[] memory underwriterOps =
            registry.getActiveOperatorsForAVS(address(registry.underwriterAVS()));
        assertEq(underwriterOps.length, 1);
        assertEq(underwriterOps[0], operator);

        // Test Validator operator queries
        address[] memory validatorOps =
            registry.getActiveOperatorsForAVS(address(registry.validatorAVS()));
        assertEq(validatorOps.length, 1);
        assertEq(validatorOps[0], operator);

        // Verify operator data
        (
            IProposerRegistry.Operator memory underwriterOpData,
            IProposerRegistry.Operator memory validatorOpData
        ) = registry.getRegisteredOperator(operator);

        // Verify Underwriter operator data
        assertEq(underwriterOpData.operatorAddress, operator);
        assertEq(
            uint256(underwriterOpData.serviceType),
            uint256(IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER)
        );
        assertEq(keccak256(underwriterOpData.blsKey), keccak256(mockBlsPubKey));

        // Verify Validator operator data
        assertEq(validatorOpData.operatorAddress, operator);
        assertEq(
            uint256(validatorOpData.serviceType),
            uint256(IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR)
        );
        assertEq(validatorOpData.blsKey.length, 0);
    }

    function test_RegisterOperatorRevertsIfAlreadyRegistered() public {
        // First time success
        vm.prank(address(registry.underwriterAVS()));
        registry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            mockBlsPubKey
        );

        // Second time revert
        vm.prank(address(registry.underwriterAVS()));
        vm.expectRevert(bytes("Already registered"));
        registry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            mockBlsPubKey
        );
    }

    function test_RegisterOperatorRevertsIfNotCalledByMiddleware() public {
        vm.expectRevert(bytes("Unauthorized middleware"));
        registry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            mockBlsPubKey
        );
    }

    /// @notice Test operator deregistration with active validators
    function test_DeregisterOperatorRevertsWithActiveValidators() public {
        // Setup operator and validator
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(address(registry.validatorAVS()));
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Attempt to deregister with active validator should fail
        vm.prank(address(registry.validatorAVS()));
        vm.expectRevert(TaiyiProposerRegistry.CannotDeregisterActiveValidator.selector);
        registry.deregisterOperator(operator);
    }

    /// @notice Test operator deregistration with validators in cooldown
    function test_DeregisterOperatorRevertsInCooldown() public {
        // Setup operator and validator
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(address(registry.validatorAVS()));
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Initiate opt-out
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        vm.startPrank(address(registry.validatorAVS()), operator);
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        vm.stopPrank();

        // Attempt to deregister during cooldown should fail
        vm.prank(address(registry.validatorAVS()));
        vm.expectRevert(TaiyiProposerRegistry.CannotDeregisterInCooldown.selector);
        registry.deregisterOperator(operator);
    }

    /// @notice Test successful operator deregistration after validator opt-out
    function test_SuccessfulDeregistrationAfterOptOut() public {
        // Setup operator and validator
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(address(registry.validatorAVS()));
        registry.registerValidator(validatorPubkey, operator, delegatee);

        // Complete opt-out process
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        vm.prank(address(registry.validatorAVS()));
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);
        registry.confirmOptOut(pubkeyHash);

        // Deregister operator
        vm.prank(address(registry.validatorAVS()));
        registry.deregisterOperator(operator);

        // Verify operator is fully deregistered
        assertFalse(
            registry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            )
        );
        assertFalse(
            registry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            )
        );

        // Verify operator data is cleared
        (
            IProposerRegistry.Operator memory underwriterOpData,
            IProposerRegistry.Operator memory validatorOpData
        ) = registry.getRegisteredOperator(operator);
        underwriterOpData;
        assertEq(validatorOpData.operatorAddress, address(0));
        assertEq(validatorOpData.restakingMiddlewareContract, address(0));
        assertEq(validatorOpData.blsKey.length, 0);
    }

    /// @notice Test post-deregistration restrictions
    function test_PostDeregistrationRestrictions() public {
        // Setup and deregister operator with opted out validator
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        vm.prank(address(registry.validatorAVS()));
        registry.registerValidator(validatorPubkey, operator, delegatee);

        bytes32 pubkeyHash = keccak256(validatorPubkey);
        vm.prank(address(registry.validatorAVS()));
        registry.initOptOut(pubkeyHash, block.timestamp + 1 days);
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);
        registry.confirmOptOut(pubkeyHash);

        vm.prank(address(registry.validatorAVS()));
        registry.deregisterOperator(operator);

        // Attempt post-deregistration actions
        vm.startPrank(address(registry.validatorAVS()));

        // Should not be able to register new validators
        bytes memory newValidatorPubkey = new bytes(48);
        vm.expectRevert("Operator not registered with correct service");
        registry.registerValidator(newValidatorPubkey, operator, delegatee);

        // Should be able to register as operator again since they were deregistered
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        // Verify validator count is zero
        assertEq(registry.getValidatorCountForOperatorInAVS(operator), 0);
        vm.stopPrank();
    }

    /// @notice Test deregistration with multiple validators
    function test_DeregistrationWithMultipleValidators() public {
        // Setup operator
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

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

            vm.prank(address(registry.validatorAVS()));
            registry.registerValidator(pubkeys[i], operator, delegatees[i]);
        }

        // Opt out all validators
        vm.startPrank(address(registry.validatorAVS()), operator);
        for (uint256 i = 0; i < validatorCount; i++) {
            registry.initOptOut(pubkeyHashes[i], block.timestamp + 1 days);
        }
        vm.stopPrank();

        // Wait cooldown and confirm opt-out for all
        vm.warp(block.timestamp + registry.OPT_OUT_COOLDOWN() + 1);
        for (uint256 i = 0; i < validatorCount; i++) {
            registry.confirmOptOut(pubkeyHashes[i]);
        }

        // Verify events for multiple validators
        vm.prank(address(registry.validatorAVS()));

        vm.prank(address(registry.validatorAVS()));
        // Deregister operator
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
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        // Create test validator pubkey and delegatee
        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatee = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xcd;
            delegatee[i] = 0xef;
        }

        // Register validator
        vm.prank(address(registry.validatorAVS()));
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
        vm.prank(address(registry.validatorAVS()));
        registry.registerOperator(
            operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR, ""
        );

        bytes memory validatorPubkey = new bytes(48);
        bytes memory emptyDelegatee = "";

        // Should revert when trying to register with empty delegatee
        vm.prank(address(registry.validatorAVS()));
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
            IProposerRegistry.RestakingServiceType serviceType,
            bytes memory blsKey
        )
    {
        (
            IProposerRegistry.Operator memory underwriterOp,
            IProposerRegistry.Operator memory validatorOp
        ) = registry.getRegisteredOperator(operatorAddr);
        validatorOp;
        return (
            underwriterOp.operatorAddress,
            underwriterOp.restakingMiddlewareContract,
            underwriterOp.serviceType,
            underwriterOp.blsKey
        );
    }

    function test_ProtocolSpecificBLSKeyUpdate() public {
        // Register as EigenLayer Underwriter operator
        vm.prank(address(registry.underwriterAVS()));
        registry.registerOperator(
            operator,
            IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            mockBlsPubKey
        );

        bytes memory newBlsKey = new bytes(48);
        vm.prank(operator);
        registry.updateOperatorBLSKey(operator, newBlsKey);

        (IProposerRegistry.Operator memory underwriterOp,) =
            registry.getOperatorData(operator);
        assertEq(keccak256(underwriterOp.blsKey), keccak256(newBlsKey));
        assertEq(
            uint256(underwriterOp.serviceType),
            uint256(IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER)
        );
    }
}
