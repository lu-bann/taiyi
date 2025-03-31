// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { ERC20PresetFixedSupplyUpgradeable } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-upgradeable-v4.9.0/contracts/token/ERC20/presets/ERC20PresetFixedSupplyUpgradeable.sol";

import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "@eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IDelegationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";

import { IAVSRegistrar } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import { IEigenPod } from "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IEigenPodTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { console } from "forge-std/console.sol";

import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EigenLayerMiddleware } from "src/eigenlayer-avs/EigenLayerMiddleware.sol";

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";

import { IPubkeyRegistry } from "src/interfaces/IPubkeyRegistry.sol";
import { PubkeyRegistry } from "src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "src/operator-registries/SocketRegistry.sol";
import { TaiyiRegistryCoordinator } from
    "src/operator-registries/TaiyiRegistryCoordinator.sol";

import { StdUtils } from "forge-std/StdUtils.sol";
import "forge-std/Test.sol";
import { BLS12381 } from "src/libs/BLS12381.sol";
import { BN254 } from "src/libs/BN254.sol";

import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract EigenlayerMiddlewareTest is Test {
    using BLS12381 for BLS12381.G1Point;

    address public eigenLayerMiddleware; // Changed to address instead of a contract type
    EigenlayerDeployer public eigenLayerDeployer;
    TaiyiRegistryCoordinator public registryCoordinator;
    address public owner;
    address staker;
    address operator;
    address rewardsInitiator;
    uint256 operatorSecretKey;
    bytes operatorBLSPubKey;

    uint256 constant STAKE_AMOUNT = 32 ether;
    uint256 constant UNDERWRITER_SHARE_BIPS = 8000; // 80%
    uint256 constant _WAD = 1e18; // 1 WAD = 100% allocation (with underscore to fix linter)

    uint32 public operatorSetId; // Store the operator set ID created in setUp

    // Events to track
    event ValidatorOperatorRegistered(
        address indexed operator,
        address indexed avs,
        bytes delegatedGatewayPubKey,
        bytes validatorPubKey
    );

    // Modifiers
    modifier impersonate(address user) {
        vm.startPrank(user);
        _;
        vm.stopPrank();
    }

    /// @notice Performs initial setup for the test environment by deploying and initializing contracts
    function setUp() public {
        eigenLayerDeployer = new EigenlayerDeployer();
        staker = eigenLayerDeployer.setUp();

        (operator, operatorSecretKey) = makeAddrAndKey("operator");
        owner = makeAddr("owner");
        rewardsInitiator = makeAddr("rewardInitiator");
        address proxyAdmin = makeAddr("proxyAdmin");

        // Transfer some WETH to the operator so they can stake
        vm.startPrank(address(eigenLayerDeployer));
        eigenLayerDeployer.weth().transfer(operator, 100 ether);
        vm.stopPrank();

        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }

        vm.startPrank(owner);

        // First, create the registry coordinator implementation
        TaiyiRegistryCoordinator registryImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(eigenLayerDeployer.allocationManager()),
            IPauserRegistry(eigenLayerDeployer.eigenLayerPauserReg()),
            "TaiyiRegistryCoordinator"
        );

        // Now create a proxy for the registry coordinator with the right initialization data
        bytes memory initData = abi.encodeWithSelector(
            TaiyiRegistryCoordinator.initialize.selector,
            owner, // initialOwner
            0, // initialPausedStatus
            address(eigenLayerDeployer.allocationManager()), // _allocationManager
            address(eigenLayerDeployer.eigenLayerPauserReg()) // _pauserRegistry
        );

        TransparentUpgradeableProxy registryProxy =
            new TransparentUpgradeableProxy(address(registryImpl), proxyAdmin, initData);

        registryCoordinator = TaiyiRegistryCoordinator(address(registryProxy));

        PubkeyRegistry pubkeyRegistry = new PubkeyRegistry(registryCoordinator);
        SocketRegistry socketRegistry = new SocketRegistry(registryCoordinator);

        // Update the registry coordinator to use the new registries
        registryCoordinator.updateSocketRegistry(address(socketRegistry));

        // Update the pubkey registry in the registry coordinator
        registryCoordinator.updatePubkeyRegistry(address(pubkeyRegistry));

        // Store this test contract address as middleware
        eigenLayerMiddleware = address(this);

        // Set this test contract as the EigenLayerMiddleware
        registryCoordinator.setEigenlayerMiddleware(eigenLayerMiddleware);

        // Set this test contract as the AVS registrar for AllocationManager
        // This ensures that AllocationManager will call back to our registerOperator function
        vm.startPrank(eigenLayerMiddleware);
        eigenLayerDeployer.allocationManager().setAVSRegistrar(
            eigenLayerMiddleware, IAVSRegistrar(registryCoordinator)
        );
        vm.stopPrank();

        // We need to register our middleware with the AllocationManager as an AVS
        // Create an operator set through the EigenLayer allocation manager directly
        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        // Use the same strategies the EigenlayerDeployer uses
        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IStrategy(eigenLayerDeployer.wethStrat());

        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: 0, // First operator set
            strategies: strategies
        });

        // Call createOperatorSets directly on the AllocationManager
        vm.stopPrank();
        vm.prank(eigenLayerMiddleware);
        IAllocationManager(eigenLayerDeployer.allocationManager()).createOperatorSets(
            eigenLayerMiddleware, createSetParams
        );

        // Store this ID for later use
        operatorSetId = 0; // The first operator set we created
    }

    // Full EigenLayer and AVS registration flow
    function _registerCompleteOperator(
        address _operator,
        uint32 operatorSetId,
        bytes memory extraData
    )
        internal
    {
        // 1. Register in EigenLayer
        _registerOperatorInEigenLayer(_operator);

        // 2. Stake into EigenLayer to have active stake
        _stakeIntoEigenLayer(_operator, STAKE_AMOUNT);

        // 3. Allocate stake to the AVS (step 1 of AVS opt-in)
        _allocateStakeToAVS(_operator, operatorSetId);

        // 4. Register for the operator set (step 2 of AVS opt-in)
        _registerForOperatorSets(_operator, operatorSetId, extraData);
    }

    // Helper function to register an operator in EigenLayer
    function _registerOperatorInEigenLayer(address _operator) internal {
        // First register the operator with EigenLayer
        vm.startPrank(_operator);
        eigenLayerDeployer.delegation().registerAsOperator(
            address(0), // No delegation approver, anyone can delegate
            0, // No allocation delay
            "https://taiyi.xyz/metadata"
        );
        vm.stopPrank();
    }

    // Helper function to stake ETH to get active stake in EigenLayer
    function _stakeIntoEigenLayer(
        address _staker,
        uint256 amount
    )
        internal
        impersonate(_staker)
        returns (uint256 shares)
    {
        // Approve and deposit ETH into the EigenLayer strategy
        eigenLayerDeployer.weth().approve(
            address(eigenLayerDeployer.strategyManager()), amount
        );

        shares = eigenLayerDeployer.strategyManager().depositIntoStrategy(
            eigenLayerDeployer.wethStrat(), eigenLayerDeployer.weth(), amount
        );
    }

    // Helper function to allocate stake to an AVS (step 1 of AVS opt-in)
    function _allocateStakeToAVS(
        address _operator,
        uint32 operatorSetId
    )
        internal
        impersonate(_operator)
    {
        // Make sure allocation delay is set to 0 for the operator before allocation
        eigenLayerDeployer.allocationManager().setAllocationDelay(_operator, 0);

        // The allocation delay configuration takes ALLOCATION_CONFIGURATION_DELAY + 1 blocks to take effect
        // Get the current allocation delay info to see if it's already set
        (bool isSet,) =
            eigenLayerDeployer.allocationManager().getAllocationDelay(_operator);

        // If not set, we need to wait for the delay to take effect (typically 1200 blocks + 1)
        if (!isSet) {
            // Roll forward the block number by the allocation configuration delay (typically 1200) + 1
            vm.roll(block.number + 1201);
        }

        // First step of AVS opt-in: allocate stake to the AVS's operator set

        // Get the OperatorSet struct
        OperatorSet memory opSet;
        opSet.id = operatorSetId;
        opSet.avs = eigenLayerMiddleware;

        // Get strategies in the operator set
        IStrategy[] memory strategies =
            eigenLayerDeployer.allocationManager().getStrategiesInOperatorSet(opSet);

        // Set up new magnitudes array (in WAD format, 1e18 = 100% allocation)
        uint64[] memory newMagnitudes = new uint64[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            newMagnitudes[i] = uint64(_WAD); // Using _WAD for 100% allocation
        }

        // Create allocation params
        IAllocationManagerTypes.AllocateParams[] memory allocParams =
            new IAllocationManagerTypes.AllocateParams[](1);
        allocParams[0] = IAllocationManagerTypes.AllocateParams({
            operatorSet: opSet,
            strategies: strategies,
            newMagnitudes: newMagnitudes
        });

        // Call modifyAllocations with the operator address and allocation params
        eigenLayerDeployer.allocationManager().modifyAllocations(_operator, allocParams);
    }

    // Helper function to register for operator sets (step 2 of AVS opt-in)
    function _registerForOperatorSets(
        address _operator,
        uint32 operatorSetId,
        bytes memory extraData
    )
        internal
        impersonate(_operator)
    {
        // Second step of AVS opt-in: register for the operator set

        // Format the data properly as expected by TaiyiRegistryCoordinator
        // We need to encode a string (socket) and PubkeyRegistrationParams struct
        string memory socket = "operator-socket.taiyi.xyz";

        // Create a valid PubkeyRegistrationParams struct with proper values
        // In a real scenario, these would be generated from a private key
        IPubkeyRegistry.PubkeyRegistrationParams memory params;

        // Create G1 point for the pubkey
        params.pubkeyG1 = BN254.G1Point({
            X: 1_234_567_890_123_456_789_012_345_678_901_234_567_890,
            Y: 9_876_543_210_987_654_321_098_765_432_109_876_543_210
        });

        // Create G2 point for the pubkey
        params.pubkeyG2 = BN254.G2Point({
            X: [
                uint256(11_111_111_111_111_111_111_111_111_111_111_111_111),
                uint256(22_222_222_222_222_222_222_222_222_222_222_222_222)
            ],
            Y: [
                uint256(33_333_333_333_333_333_333_333_333_333_333_333_333),
                uint256(44_444_444_444_444_444_444_444_444_444_444_444_444)
            ]
        });

        // Create a signature point
        params.pubkeyRegistrationSignature = BN254.G1Point({
            X: 5_555_555_555_555_555_555_555_555_555_555_555_555_555,
            Y: 6_666_666_666_666_666_666_666_666_666_666_666_666_666
        });

        bytes memory formattedData = abi.encode(socket, params);

        IAllocationManagerTypes.RegisterParams memory registerParams =
        IAllocationManagerTypes.RegisterParams({
            avs: eigenLayerMiddleware,
            operatorSetIds: _uint32ToArray(operatorSetId),
            data: formattedData
        });

        eigenLayerDeployer.allocationManager().registerForOperatorSets(
            _operator, registerParams
        );
    }

    // Helper function to test operator opt-out/deregistration from AVS
    function _deregisterFromAVS(
        address _operator,
        uint32 operatorSetId
    )
        internal
        impersonate(_operator)
    {
        // Create the DeregisterParams struct
        IAllocationManagerTypes.DeregisterParams memory params = IAllocationManagerTypes
            .DeregisterParams({
            operator: _operator,
            avs: eigenLayerMiddleware,
            operatorSetIds: _uint32ToArray(operatorSetId)
        });

        // Deregister from the AVS's operator set
        eigenLayerDeployer.allocationManager().deregisterFromOperatorSets(params);
    }

    // Helper function to convert a single uint32 to a uint32[] array
    function _uint32ToArray(uint32 value) internal pure returns (uint32[] memory) {
        uint32[] memory array = new uint32[](1);
        array[0] = value;
        return array;
    }

    function testOperatorRegistrationFlow() public {
        // Use the operatorSetId created in setUp

        OperatorSet memory opSet;
        opSet.id = operatorSetId;
        opSet.avs = eigenLayerMiddleware;
        assertTrue(
            eigenLayerDeployer.allocationManager().isOperatorSet(opSet),
            "Operator set should exist"
        );

        // 2. Register the operator in EigenLayer, allocate stake, and register for operator set
        bytes memory extraData = abi.encode(operatorBLSPubKey);
        _registerCompleteOperator(operator, operatorSetId, extraData);

        // 3. Verify the registration was successful

        // Check operator is registered in EigenLayer
        assertTrue(
            eigenLayerDeployer.delegation().isOperator(operator),
            "Operator should be registered in EigenLayer"
        );

        // Check operator has allocated stake to the operator set
        IAllocationManager allocationManager = eigenLayerDeployer.allocationManager();

        assertTrue(
            allocationManager.isMemberOfOperatorSet(operator, opSet),
            "Operator should be a member of the operator set"
        );

        // Check operator's allocation from each strategy to the operator set
        IStrategy[] memory strategies =
            allocationManager.getStrategiesInOperatorSet(opSet);
        assertEq(strategies.length, 1, "Should have 1 strategy in operator set");

        IAllocationManagerTypes.Allocation memory allocation =
            allocationManager.getAllocation(operator, opSet, strategies[0]);

        assertEq(allocation.currentMagnitude, uint64(_WAD), "Wrong allocation magnitude");
        assertEq(int256(allocation.pendingDiff), 0, "Should have no pending diff");

        // Check operator is registered in the operator set
        address[] memory members = allocationManager.getMembers(opSet);
        bool operatorFound = false;
        for (uint256 i = 0; i < members.length; i++) {
            if (members[i] == operator) {
                operatorFound = true;
                break;
            }
        }
        assertTrue(operatorFound, "Operator should be found in operator set members");

        // 4. Test deregistration
        _deregisterFromAVS(operator, operatorSetId);

        // The operator should be marked as deregistered (but still slashable)
        assertFalse(
            allocationManager.isMemberOfOperatorSet(operator, opSet),
            "Operator should no longer be a member of the operator set after deregistration"
        );

        // Check the operator is still in the allocated sets (deallocation pending)
        OperatorSet[] memory allocatedSets = allocationManager.getAllocatedSets(operator);
        bool stillAllocated = false;
        for (uint256 i = 0; i < allocatedSets.length; i++) {
            if (
                allocatedSets[i].id == operatorSetId
                    && allocatedSets[i].avs == eigenLayerMiddleware
            ) {
                stillAllocated = true;
                break;
            }
        }
        assertTrue(
            stillAllocated,
            "Operator should still have allocations during deallocation delay"
        );
    }

    // function testGatewayOperatorAVSRegistration() public {
    //     // _operatorRegistration(operator);
    //     // _gatewayOperatorAVSRegistration(operator, operatorSecretKey, 0, operatorBLSPubKey);
    //     // assertTrue(
    //     //     proposerRegistry.isOperatorRegisteredInAVS(
    //     //         operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_GATEWAY
    //     //     ),
    //     //     "Gateway operator registration failed"
    //     // );

    //     // (
    //     //     ITaiyiRegistryCoordinator.OperatorInfo memory gatewayOpData,
    //     //     ITaiyiRegistryCoordinator.OperatorInfo memory validatorOpData
    //     // ) = registryCoordinator.getOperatorInfo(operator);
    //     // validatorOpData;
    //     // assertEq(
    //     //     keccak256(gatewayOpData.blsKey),
    //     //     keccak256(operatorBLSPubKey),
    //     //     "BLS key should match"
    //     // );
    // }

    // function testValidatorOperatorAVSRegistration() public {
    //     _operatorRegistration(operator);
    //     _validatorOperatorAVSRegistration(operator, operatorSecretKey, 0);
    //     assertTrue(
    //         proposerRegistry.isOperatorRegisteredInAVS(
    //             operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
    //         ),
    //         "Validator operator registration failed"
    //     );
    // }

    // /// @notice Tests Gateway operator registration and event emission
    // /// @dev Verifies:
    // /// 1. Operator can register with GatewayAVS
    // /// 2. BLS key is properly stored
    // /// 3. Events are emitted for preconf delegation message
    // function test_GatewayOperatorRegistration() public {
    //     // Register operator in EigenLayer first
    //     _operatorRegistration(operator);

    //     _gatewayOperatorAVSRegistration(operator, operatorSecretKey, 0, operatorBLSPubKey);

    //     // Verify registration
    //     assertTrue(
    //         proposerRegistry.isOperatorRegisteredInAVS(
    //             operator, IProposerRegistry.RestakingServiceType.EIGENLAYER_GATEWAY
    //         ),
    //         "Operator should be registered in GatewayAVS"
    //     );

    // }

    // /// @notice Tests EigenPod creation
    // /// @dev Verifies that a user can create an EigenPod and it's properly registered
    // function test_EigenPodCreation() public {
    //     address podOwner = makeAddr("podOwner");

    //     vm.startPrank(podOwner);
    //     address podAddress = validatorAVS.getEigenPodManager().createPod();
    //     vm.stopPrank();

    //     assertTrue(
    //         validatorAVS.getEigenPodManager().hasPod(podOwner), "Pod should be registered"
    //     );
    //     assertEq(
    //         address(eigenLayerDeployer.eigenPodManager().ownerToPod(podOwner)),
    //         podAddress,
    //         "Pod address should match"
    //     );
    // }

    // /// @notice Tests EigenPod delegation to an operator who's not the pod owner
    // /// @dev Verifies that a pod owner can delegate their pod to an operator
    // function test_EigenPodDelegation() public {
    //     address podOwner = makeAddr("podOwner");

    //     // Create pod
    //     vm.startPrank(podOwner);
    //     address podAddress = validatorAVS.getEigenPodManager().createPod();
    //     podAddress;
    //     vm.stopPrank();

    //     // Register operator
    //     _operatorRegistration(operator);

    //     // Delegate pod to operator
    //     vm.startPrank(podOwner);
    //     ISignatureUtils.SignatureWithExpiry memory operatorSignature =
    //         ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
    //     eigenLayerDeployer.delegation().delegateTo(
    //         operator, operatorSignature, bytes32(0)
    //     );
    //     vm.stopPrank();
    //     // Verify delegation
    //     assertEq(
    //         eigenLayerDeployer.delegation().delegatedTo(podOwner),
    //         operator,
    //         "Pod should be delegated to operator"
    //     );
    // }

    // /// @notice Tests complete validator registration flow through the middleware
    // /// including pod creation, operator setup, and validator registration
    // function test_CompleteValidatorRegistration() public {
    //     // Create and verify pod
    //     address mockPodOwner = vm.addr(1);
    //     vm.label(mockPodOwner, "mockPodOwner");

    //     vm.startPrank(mockPodOwner);
    //     address podAddress = validatorAVS.getEigenPodManager().createPod();
    //     assertTrue(
    //         eigenLayerDeployer.eigenPodManager().hasPod(mockPodOwner),
    //         "Pod should be created."
    //     );
    //     vm.stopPrank();

    //     // 3. Register operator in EigenLayer and self delegate
    //     _operatorRegistration(mockPodOwner);

    //     bytes memory mockPodOwnerBLSPubKey = new bytes(48);
    //     for (uint256 i = 0; i < 48; i++) {
    //         mockPodOwnerBLSPubKey[i] = 0xcd;
    //     }

    //     // 4. Register as Operator in GatewayAVS
    //     _gatewayOperatorAVSRegistration(mockPodOwner, 1, 0, mockPodOwnerBLSPubKey);
    //     assertTrue(
    //         proposerRegistry.isOperatorRegisteredInAVS(
    //             mockPodOwner, IProposerRegistry.RestakingServiceType.EIGENLAYER_GATEWAY
    //         ),
    //         "Operator should be registered in GatewayAVS"
    //     );

    //     // 5. Register as Operator in ValidatorAVS
    //     _validatorOperatorAVSRegistration(mockPodOwner, 1, 1);
    //     assertTrue(
    //         proposerRegistry.isOperatorRegisteredInAVS(
    //             mockPodOwner, IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
    //         ),
    //         "Operator should be registered in ValidatorAVS"
    //     );

    //     // 6. Create test validator pubkey and delegatee
    //     bytes memory validatorPubkey = new bytes(48);
    //     for (uint256 i = 0; i < 48; i++) {
    //         validatorPubkey[i] = 0xab;
    //     }
    //     _cheatValidatorPubkeyActive(podAddress, validatorPubkey);

    //     // 7. Register validator
    //     bytes[][] memory valPubKeys = new bytes[][](1);
    //     valPubKeys[0] = new bytes[](1);
    //     valPubKeys[0][0] = validatorPubkey;

    //     address[] memory podOwners = new address[](1);
    //     podOwners[0] = mockPodOwner;

    //     bytes[] memory delegatedGateways = new bytes[](1);
    //     delegatedGateways[0] = mockPodOwnerBLSPubKey;

    //     vm.prank(mockPodOwner);
    //     validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);

    //     // 8. Verify registration status in proposer registry
    //     bytes32 pubkeyHash = keccak256(validatorPubkey);
    //     ITaiyiRegistryCoordinator.ValidatorStatus validatorStatus =
    //         registryCoordinator.getValidatorStatus(pubkeyHash);
    //     assertEq(uint8(validatorStatus), uint8(ITaiyiRegistryCoordinator.ValidatorStatus.Active));

    //     // 9. Verify delegatee
    //     ITaiyiRegistryCoordinator.Validator memory validator =
    //         registryCoordinator.getValidator(pubkeyHash);
    //     assertEq(keccak256(validator.delegatee), keccak256(mockPodOwnerBLSPubKey));

    //     // 10. Verify validator status in EigenPod
    //     IEigenPod pod = validatorAVS.getEigenPodManager().getPod(mockPodOwner);
    //     IEigenPod.ValidatorInfo memory info = pod.validatorPubkeyToInfo(validatorPubkey);
    //     assertEq(uint8(info.status), uint8(IEigenPodTypes.VALIDATOR_STATUS.ACTIVE));
    // }

    // /// @notice Tests validator registration in ValidatorAVS
    // /// @dev Verifies:
    // /// 1. Multiple validators can be registered
    // /// 2. Each validator has correct delegatee
    // /// 3. Events are emitted correctly
    // /// 4. Validator counts are tracked
    // function test_MultipleValidatorRegistration() public {
    //     address podOwner = makeAddr("podOwner");

    //     // Setup pod and operator
    //     vm.startPrank(podOwner);
    //     address podAddress = validatorAVS.getEigenPodManager().createPod();
    //     vm.stopPrank();

    //     // Register operator in EigenLayer
    //     _operatorRegistration(operator);
    //     _delegationToOperator(podOwner, operator);

    //     // Register operator in both AVS
    //     _gatewayOperatorAVSRegistration(operator, operatorSecretKey, 0, operatorBLSPubKey);
    //     _validatorOperatorAVSRegistration(operator, operatorSecretKey, 1);

    //     // Prepare multiple validator keys
    //     uint256 validatorCount = 3;
    //     bytes[][] memory valPubKeys = new bytes[][](1);
    //     valPubKeys[0] = new bytes[](validatorCount);
    //     bytes[] memory delegatedGateways = new bytes[](1);
    //     delegatedGateways[0] = operatorBLSPubKey; // Use operator's BLS key as delegatee
    //     address[] memory podOwners = new address[](1);
    //     podOwners[0] = podOwner;

    //     for (uint256 i = 0; i < validatorCount; i++) {
    //         valPubKeys[0][i] = new bytes(48);
    //         for (uint256 j = 0; j < 48; j++) {
    //             valPubKeys[0][i][j] = bytes1(uint8(0xab + i));
    //         }
    //         _cheatValidatorPubkeyActive(podAddress, valPubKeys[0][i]);
    //     }

    //     // Register validators
    //     vm.prank(podOwner);
    //     validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);

    //     // Verify registrations
    //     for (uint256 i = 0; i < validatorCount; i++) {
    //         bytes32 pubkeyHash = keccak256(valPubKeys[0][i]);
    //         IProposerRegistry.Validator memory validator =
    //             proposerRegistry.getValidator(pubkeyHash);

    //         assertEq(validator.operator, operator, "Wrong operator");
    //         assertEq(
    //             keccak256(validator.delegatee),
    //             keccak256(operatorBLSPubKey),
    //             "Wrong delegatee"
    //         );
    //         assertEq(
    //             uint8(validator.status),
    //             uint8(IProposerRegistry.ValidatorStatus.Active),
    //             "Wrong status"
    //         );
    //     }

    //     // Verify validator count
    //     assertEq(
    //         proposerRegistry.getValidatorCountForOperatorInAVS(operator),
    //         validatorCount,
    //         "Wrong validator count"
    //     );
    // }

    // /// @notice Tests reward distribution between GatewayAVS and ValidatorAVS
    // function test_RewardDistribution() public {
    //     // Setup reward token and get shares
    //     (IERC20 rewardToken, uint256 gatewayShare, uint256 validatorShare) =
    //         _setupRewardToken();
    //     validatorShare;

    //     // Setup operators
    //     (
    //         address gatewayOp,
    //         address validatorOp1,
    //         address validatorOp2,
    //         uint256 gatewayOpKey,
    //         uint256 validatorOp1Key,
    //         uint256 validatorOp2Key
    //     ) = _setupOperators();
    //     gatewayOpKey;

    //     // Setup validator operators in both AVSs
    //     _setupValidatorOperatorsInAVS(
    //         validatorOp1, validatorOp2, validatorOp1Key, validatorOp2Key
    //     );

    //     IRewardsCoordinator.StrategyAndMultiplier[] memory strategyAndMultipliers =
    //         new IRewardsCoordinatorTypes.StrategyAndMultiplier[](1);
    //     strategyAndMultipliers[0] = IRewardsCoordinatorTypes.StrategyAndMultiplier({
    //         strategy: eigenLayerDeployer.wethStrat(),
    //         multiplier: 1 ether
    //     });

    //     // First submission: Gateway rewards
    //     IRewardsCoordinator.OperatorReward[] memory gatewayRewards =
    //         new IRewardsCoordinator.OperatorReward[](3);

    //     // Create rewards with operators (already in ascending order from _setupOperators)
    //     gatewayRewards[0] = IRewardsCoordinatorTypes.OperatorReward({
    //         operator: gatewayOp,
    //         amount: gatewayShare
    //     });
    //     gatewayRewards[1] =
    //         IRewardsCoordinatorTypes.OperatorReward({ operator: validatorOp1, amount: 0 });
    //     gatewayRewards[2] =
    //         IRewardsCoordinatorTypes.OperatorReward({ operator: validatorOp2, amount: 0 });

    //     // Second submission: Validator rewards (with sorted operators)
    //     IRewardsCoordinatorTypes.OperatorReward[] memory validatorRewards =
    //         new IRewardsCoordinatorTypes.OperatorReward[](2);
    //     validatorRewards[0] =
    //         IRewardsCoordinatorTypes.OperatorReward({ operator: validatorOp1, amount: 0 });
    //     validatorRewards[1] =
    //         IRewardsCoordinatorTypes.OperatorReward({ operator: validatorOp2, amount: 0 });

    //     // Create the submissions array
    //     IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
    //         new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](2);

    //     _warpToNextInterval(7 days + 1);

    //     // Gateway submission
    //     submissions[0] = IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission({
    //         strategiesAndMultipliers: strategyAndMultipliers,
    //         token: rewardToken,
    //         operatorRewards: gatewayRewards,
    //         startTimestamp: uint32(block.timestamp - 14 days),
    //         duration: 7 days,
    //         description: "gateway"
    //     });

    //     // Validator submission
    //     submissions[1] = IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission({
    //         strategiesAndMultipliers: strategyAndMultipliers,
    //         token: rewardToken,
    //         operatorRewards: validatorRewards,
    //         startTimestamp: uint32(block.timestamp - 14 days),
    //         duration: 7 days,
    //         description: "validator"
    //     });

    //     uint256 beforeBal =
    //         rewardToken.balanceOf(address(eigenLayerDeployer.rewardsCoordinator()));

    //     vm.expectEmit(true, true, false, true);
    //     emit GatewayAVS.ValidatorAmountForwarded(200 ether); // 1000 ether * 20%

    //     // Submit rewards as rewardsInitiator
    //     vm.prank(rewardsInitiator);
    //     gatewayAVS.createOperatorDirectedAVSRewardsSubmission(submissions);

    //     uint256 afterBal =
    //         rewardToken.balanceOf(address(eigenLayerDeployer.rewardsCoordinator()));

    //     assertApproxEqAbs(
    //         afterBal,
    //         beforeBal + 1000e18,
    //         1,
    //         "Coordinator balance should have increased by 1000 tokens"
    //     );

    //     // Todo: test the processClaim
    //     // vm.prank(gatewayOp);
    //     // gatewayAVS.processClaim(gatewayOp, address(rewardToken));
    //     // assertApproxEqAbs(
    //     //     rewardToken.balanceOf(gatewayOp), gatewayShare, 1, "Wrong gateway reward"
    //     // );
    //     // assertApproxEqAbs(
    //     //     rewardToken.balanceOf(validatorOp1),
    //     //     (validatorShare * 2) / 3,
    //     //     1,
    //     //     "Wrong validator1 reward"
    //     // );
    //     // assertApproxEqAbs(
    //     //     rewardToken.balanceOf(validatorOp2),
    //     //     validatorShare / 3,
    //     //     1,
    //     //     "Wrong validator2 reward"
    //     // );
    // }

    // function _warpToNextInterval(uint256 secondsToAdd) internal {
    //     uint32 interval =
    //         eigenLayerDeployer.rewardsCoordinator().CALCULATION_INTERVAL_SECONDS();
    //     uint32 startTimestamp = uint32(block.timestamp + 1000 days); // time travel baby
    //     uint256 warpTarget = startTimestamp + secondsToAdd;
    //     uint256 alignedWarp = (warpTarget / interval) * interval;
    //     if (alignedWarp <= warpTarget) {
    //         alignedWarp += interval;
    //     }
    //     vm.warp(alignedWarp);
    // }

    // /// @notice Helper function to setup reward token and transfer initial amount
    // function _setupRewardToken() internal returns (IERC20, uint256, uint256) {
    //     ERC20PresetFixedSupplyUpgradeable rewardToken =
    //         new ERC20PresetFixedSupplyUpgradeable();
    //     rewardToken.initialize("Mock Reward Token", "MRT", 2000 ether, rewardsInitiator);
    //     IERC20 reward = IERC20(address(rewardToken));

    //     uint256 totalReward = 1000 ether;
    //     uint256 gatewayShare = totalReward;

    //     // First approve gatewayAVS to spend tokens from rewardsInitiator
    //     vm.startPrank(rewardsInitiator);
    //     reward.approve(address(gatewayAVS), type(uint256).max);
    //     vm.stopPrank();

    //     // Then approve RewardsCoordinator to spend tokens from gatewayAVS
    //     vm.prank(address(gatewayAVS));
    //     reward.approve(
    //         address(eigenLayerDeployer.rewardsCoordinator()), type(uint256).max
    //     );

    //     return (reward, gatewayShare, 0 ether);
    // }

    // /// @notice Helper function to setup operators
    // function _setupOperators()
    //     internal
    //     returns (
    //         address gatewayOp,
    //         address validatorOp1,
    //         address validatorOp2,
    //         uint256 gatewayOpKey,
    //         uint256 validatorOp1Key,
    //         uint256 validatorOp2Key
    //     )
    // {
    //     // Create operators in ascending order by manipulating the labels
    //     (gatewayOp, gatewayOpKey) = makeAddrAndKey("aaa_gateway1");
    //     (validatorOp1, validatorOp1Key) = makeAddrAndKey("bbb_validator1");
    //     (validatorOp2, validatorOp2Key) = makeAddrAndKey("ccc_validator2");

    //     _setupOperator(gatewayOp, true, gatewayOpKey);
    //     _setupOperator(validatorOp1, false, validatorOp1Key);
    //     _setupOperator(validatorOp2, false, validatorOp2Key);
    // }

    // /// @notice Helper function to setup validator operators in AVS
    // function _setupValidatorOperatorsInAVS(
    //     address validatorOp1,
    //     address validatorOp2,
    //     uint256 validatorOp1Key,
    //     uint256 validatorOp2Key
    // )
    //     internal
    // {
    //     bytes memory validatorOp1BLSPubKey = _generateMockBLSKey();
    //     bytes memory validatorOp2BLSPubKey = _generateMockBLSKey();

    //     _gatewayOperatorAVSRegistration(
    //         validatorOp1, validatorOp1Key, 1, validatorOp1BLSPubKey
    //     );
    //     _gatewayOperatorAVSRegistration(
    //         validatorOp2, validatorOp2Key, 2, validatorOp2BLSPubKey
    //     );

    //     vm.startPrank(validatorOp1);
    //     validatorAVS.getEigenPodManager().createPod();
    //     vm.stopPrank();

    //     vm.startPrank(validatorOp2);
    //     validatorAVS.getEigenPodManager().createPod();
    //     vm.stopPrank();

    //     _registerValidatorsForOperator(validatorOp1, 2); // First operator has 2 validators
    //     _registerValidatorsForOperator(validatorOp2, 1); // Second operator has 1 validator
    // }

    // function _generateMockBLSKey() internal pure returns (bytes memory) {
    //     bytes memory blsKey = new bytes(48);
    //     for (uint256 i = 0; i < 48; i++) {
    //         blsKey[i] = bytes1(uint8(0xab + i));
    //     }
    //     return blsKey;
    // }

    // /// @notice Helper function to create gateway rewards submission
    // function _createGatewayRewardsSubmission(
    //     IERC20 rewardToken,
    //     address gatewayOperator1,
    //     address gatewayOperator2,
    //     uint256 gatewayShare
    // )
    //     internal
    //     view
    //     returns (IRewardsCoordinator.OperatorDirectedRewardsSubmission memory)
    // {
    //     IRewardsCoordinator.OperatorReward[] memory gatewayRewards =
    //         new IRewardsCoordinatorTypes.OperatorReward[](2);
    //     gatewayRewards[0] = IRewardsCoordinatorTypes.OperatorReward({
    //         operator: gatewayOperator1,
    //         amount: gatewayShare / 2
    //     });
    //     gatewayRewards[1] = IRewardsCoordinatorTypes.OperatorReward({
    //         operator: gatewayOperator2,
    //         amount: gatewayShare / 2
    //     });

    //     return IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission({
    //         strategiesAndMultipliers: new IRewardsCoordinatorTypes.StrategyAndMultiplier[](0),
    //         token: rewardToken,
    //         operatorRewards: gatewayRewards,
    //         startTimestamp: uint32(block.timestamp),
    //         duration: 7 days,
    //         description: "gateway"
    //     });
    // }

    // /// @notice Helper function to create validator rewards submission
    // function _createValidatorRewardsSubmission(
    //     IERC20 rewardToken,
    //     address validatorOperator1,
    //     address validatorOperator2,
    //     uint256 validatorShare
    // )
    //     internal
    //     view
    //     returns (IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission memory)
    // {
    //     IRewardsCoordinatorTypes.OperatorReward[] memory validatorRewards =
    //         new IRewardsCoordinatorTypes.OperatorReward[](2);
    //     validatorRewards[0] = IRewardsCoordinatorTypes.OperatorReward({
    //         operator: validatorOperator1,
    //         amount: (validatorShare * 2) / 3 // 2/3 of validator share (2 validators)
    //      });
    //     validatorRewards[1] = IRewardsCoordinatorTypes.OperatorReward({
    //         operator: validatorOperator2,
    //         amount: validatorShare / 3 // 1/3 of validator share (1 validator)
    //      });

    //     return IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission({
    //         strategiesAndMultipliers: new IRewardsCoordinatorTypes.StrategyAndMultiplier[](0),
    //         token: rewardToken,
    //         operatorRewards: validatorRewards,
    //         startTimestamp: uint32(block.timestamp),
    //         duration: 7 days,
    //         description: "validator"
    //     });
    // }

    // function _setupOperator(
    //     address localOperator,
    //     bool isGateway,
    //     uint256 localOperatorSecretKey
    // )
    //     internal
    //     impersonate(localOperator)
    // {
    //     bytes memory blsKey = isGateway ? new bytes(48) : bytes("");
    //     if (isGateway) {
    //         for (uint256 i = 0; i < 48; i++) {
    //             blsKey[i] = 0xab;
    //         }
    //     }

    //     eigenLayerDeployer.delegation().registerAsOperator(
    //         address(0), 0, "https://taiyi.wtf"
    //     );

    //     ISignatureUtils.SignatureWithSaltAndExpiry memory sig = _getOperatorSignature(
    //         isGateway ? address(gatewayAVS) : address(validatorAVS),
    //         localOperator,
    //         localOperatorSecretKey,
    //         0
    //     );

    //     if (isGateway) {
    //         gatewayAVS.registerOperatorToAVSWithPubKey(localOperator, sig, blsKey);
    //     } else {
    //         validatorAVS.registerOperatorToAVS(localOperator, sig);
    //     }
    // }

    // function _registerValidatorsForOperator(
    //     address localOperator,
    //     uint256 count
    // )
    //     internal
    // {
    //     bytes[][] memory valPubKeys = new bytes[][](1);
    //     valPubKeys[0] = new bytes[](count);
    //     bytes[] memory delegatedGateways = new bytes[](1);
    //     delegatedGateways[0] = operatorBLSPubKey;
    //     address[] memory podOwners = new address[](1);
    //     podOwners[0] = localOperator;

    //     address podAddress =
    //         address(validatorAVS.getEigenPodManager().ownerToPod(localOperator));
    //     for (uint256 i = 0; i < count; i++) {
    //         valPubKeys[0][i] = new bytes(48);
    //         for (uint256 j = 0; j < 48; j++) {
    //             // Use both operator address and index to ensure uniqueness
    //             if (j < 20) {
    //                 valPubKeys[0][i][j] =
    //                     bytes1(uint8(uint256(uint160(localOperator)) >> (8 * (19 - j))));
    //             } else {
    //                 valPubKeys[0][i][j] = bytes1(uint8(i + 1));
    //             }
    //         }
    //         _cheatValidatorPubkeyActive(podAddress, valPubKeys[0][i]);
    //     }

    //     vm.prank(localOperator);
    //     validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);
    // }

    // /// @notice Helper function to simulate a validator being active in EigenLayer by manipulating storage
    // function _cheatValidatorPubkeyActive(
    //     address podAddress,
    //     bytes memory pubkey
    // )
    //     internal
    // {
    //     // The contract uses sha256 on (pubkey || bytes16(0)).
    //     //    So replicate that here, to match exactly.
    //     bytes32 pubkeyHash = sha256(abi.encodePacked(pubkey, bytes16(0)));

    //     // The _validatorPubkeyHashToInfo mapping is at storage slot 54 on EigenPod.sol
    //     //    via 'forge inspect lib/eigenlayer-contracts/src/contracts/pods/EigenPod.sol:EigenPod storage'
    //     //    Key is keccak256(pubkeyHash, 54).
    //     bytes32 infoSlot = keccak256(abi.encode(pubkeyHash, uint256(54)));

    //     // Fill in the ValidatorInfo fields. If VALIDATOR_STATUS.ACTIVE = 1,
    //     //    we shift 1 by 192 bits for the status portion:
    //     uint64 validatorIndex = 123;
    //     uint64 restakedBalanceGwei = 32_000_000_000; // example: 32 ETH in Gwei
    //     uint64 lastCheckpointedAt = 9_999_999_999; // arbitrary placeholder
    //     uint256 statusActive = 1 << 192; // 1 = ACTIVE in IEigenPod.VALIDATOR_STATUS

    //     // Pack them into one 256-bit word.
    //     uint256 packed = uint256(validatorIndex);
    //     packed |= uint256(restakedBalanceGwei) << 64;
    //     packed |= uint256(lastCheckpointedAt) << 128;
    //     packed |= statusActive;

    //     vm.store(podAddress, infoSlot, bytes32(packed));
    // }

    // /// @notice Registers an operator in the DelegationManager
    // function _operatorRegistration(address localOperator)
    //     internal
    //     impersonate(localOperator)
    // {
    //     eigenLayerDeployer.delegation().registerAsOperator(
    //         address(0), 0, "https://taiyi.wtf"
    //     );
    // }

    // /// @notice Stakes WETH tokens through the EigenLayer strategy
    // function _stakeWETH() internal impersonate(staker) returns (uint256 shares) {
    //     eigenLayerDeployer.weth().approve(
    //         address(eigenLayerDeployer.strategyManager()), 69 ether
    //     );

    //     shares = eigenLayerDeployer.strategyManager().depositIntoStrategy(
    //         eigenLayerDeployer.wethStrat(), eigenLayerDeployer.weth(), 69 ether
    //     );
    // }

    // /// @notice Delegates the staker to the operator within the DelegationManager
    // function _delegationToOperator(
    //     address delegator,
    //     address delegateeOperator
    // )
    //     internal
    //     impersonate(delegator)
    // {
    //     ISignatureUtils.SignatureWithExpiry memory delegateeSignature =
    //         ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
    //     eigenLayerDeployer.delegation().delegateTo(
    //         delegateeOperator, delegateeSignature, bytes32(0)
    //     );
    // }

    // /// @notice Registers operator with Gateway AVS using signed message
    // function _gatewayOperatorAVSRegistration(
    //     address localOperator,
    //     uint256 localOperatorSecretKey,
    //     uint256 salt,
    //     bytes memory blsPubKey
    // )
    //     internal
    //     impersonate(localOperator)
    // {
    //     ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
    //     _getOperatorSignature(
    //         address(gatewayAVS), localOperator, localOperatorSecretKey, salt
    //     );
    //     gatewayAVS.registerOperatorToAVSWithPubKey(
    //         localOperator, operatorSignature, blsPubKey
    //     );
    // }

    // /// @notice Registers operator with Validator AVS using signed message
    // function _validatorOperatorAVSRegistration(
    //     address localOperator,
    //     uint256 localOperatorSecretKey,
    //     uint256 salt
    // )
    //     internal
    //     impersonate(localOperator)
    // {
    //     ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
    //     _getOperatorSignature(
    //         address(validatorAVS), localOperator, localOperatorSecretKey, salt
    //     );
    //     validatorAVS.registerOperatorToAVS(localOperator, operatorSignature);
    // }

    // /// @notice Generates operator signature for AVS registration
    // function _getOperatorSignature(
    //     address avs,
    //     address localOperator,
    //     uint256 localOperatorSecretKey,
    //     uint256 salt
    // )
    //     internal
    //     view
    //     returns (ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    // {
    //     bytes32 digest = eigenLayerDeployer.avsDirectory()
    //         .calculateOperatorAVSRegistrationDigestHash({
    //         operator: localOperator,
    //         avs: avs,
    //         salt: bytes32(salt),
    //         expiry: type(uint256).max
    //     });
    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(localOperatorSecretKey, digest);
    //     bytes memory sig = abi.encodePacked(r, s, v);
    //     operatorSignature = ISignatureUtils.SignatureWithSaltAndExpiry(
    //         sig, bytes32(salt), type(uint256).max
    //     );
    // }
}
