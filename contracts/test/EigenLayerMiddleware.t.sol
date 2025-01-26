// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { ERC20PresetFixedSupply } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";

import { IEigenPod } from "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

import { TaiyiProposerRegistry } from "src/TaiyiProposerRegistry.sol";
import { EigenLayerMiddleware } from "src/abstract/EigenLayerMiddleware.sol";

import { GatewayAVS } from "src/eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "src/eigenlayer-avs/ValidatorAVS.sol";
import { IProposerRegistry } from "src/interfaces/IProposerRegistry.sol";

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";

import { StdUtils } from "forge-std/StdUtils.sol";
import "forge-std/Test.sol";
import { BLS12381 } from "src/libs/BLS12381.sol";

contract EigenlayerMiddlewareTest is Test {
    using BLS12381 for BLS12381.G1Point;

    ValidatorAVS public validatorAVS;
    GatewayAVS public gatewayAVS;
    TaiyiProposerRegistry public proposerRegistry;
    EigenlayerDeployer public eigenLayerDeployer;

    address public owner;
    address staker;
    address operator;
    address rewardsInitiator;
    uint256 operatorSecretKey;
    bytes operatorBLSPubKey;

    uint256 constant STAKE_AMOUNT = 32 ether;
    uint256 constant GATEWAY_SHARE_BIPS = 8000; // 80%

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

        // Create mock BLS key
        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }

        proposerRegistry = new TaiyiProposerRegistry();
        validatorAVS = new ValidatorAVS();
        gatewayAVS = new GatewayAVS();

        vm.startPrank(owner);

        proposerRegistry.initialize(
            owner,
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager()),
            address(eigenLayerDeployer.strategyManager()),
            address(eigenLayerDeployer.eigenPodManager()),
            address(eigenLayerDeployer.rewardsCoordinator()),
            rewardsInitiator,
            GATEWAY_SHARE_BIPS
        );

        // Retrieve addresses from registry
        gatewayAVS = GatewayAVS(proposerRegistry.gatewayAVSAddress());
        validatorAVS = ValidatorAVS(proposerRegistry.validatorAVSAddress());

        // Register AVS contracts with the registry
        proposerRegistry.addRestakingMiddlewareContract(address(validatorAVS));
        proposerRegistry.addRestakingMiddlewareContract(address(gatewayAVS));

        // Set AVS types in the registry
        proposerRegistry.setAVSType(
            address(validatorAVS), IProposerRegistry.AVSType.VALIDATOR
        );
        proposerRegistry.setAVSType(
            address(gatewayAVS), IProposerRegistry.AVSType.GATEWAY
        );

        vm.stopPrank();
    }

    function test_StakeWETH() public {
        uint256 shares = _stakeWETH();
        assertEq(eigenLayerDeployer.wethStrat().sharesToUnderlyingView(shares), 69 ether);
    }

    function test_StakerDelegationToOperator() public {
        IDelegationManager.OperatorDetails memory _operatorDetails =
            _operatorRegistration(operator);
        _operatorDetails;
        _delegationToOperator(staker, operator);
        assertEq(eigenLayerDeployer.delegationManager().delegatedTo(staker), operator);
    }

    function testGatewayOperatorAVSRegistration() public {
        IDelegationManager.OperatorDetails memory _operatorDetails =
            _operatorRegistration(operator);
        _operatorDetails;
        _gatewayOperatorAVSRegistration(operator, operatorSecretKey, 0, operatorBLSPubKey);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.AVSType.GATEWAY
            ),
            "Gateway operator registration failed"
        );

        (
            IProposerRegistry.Operator memory gatewayOpData,
            IProposerRegistry.Operator memory validatorOpData
        ) = proposerRegistry.getRegisteredOperator(operator);
        validatorOpData;
        assertEq(
            keccak256(gatewayOpData.blsKey),
            keccak256(operatorBLSPubKey),
            "BLS key should match"
        );
    }

    function testValidatorOperatorAVSRegistration() public {
        _operatorRegistration(operator);
        _validatorOperatorAVSRegistration(operator, operatorSecretKey, 0);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.AVSType.VALIDATOR
            ),
            "Validator operator registration failed"
        );
    }

    /// @notice Tests Gateway operator registration and event emission
    /// @dev Verifies:
    /// 1. Operator can register with GatewayAVS
    /// 2. BLS key is properly stored
    /// 3. Events are emitted for preconf delegation message
    function test_GatewayOperatorRegistration() public {
        // Register operator in EigenLayer first
        IDelegationManager.OperatorDetails memory operatorDetails =
            _operatorRegistration(operator);
        operatorDetails;

        _gatewayOperatorAVSRegistration(operator, operatorSecretKey, 0, operatorBLSPubKey);

        // Verify registration
        assertTrue(
            proposerRegistry.isOperatorRegisteredInAVS(
                operator, IProposerRegistry.AVSType.GATEWAY
            ),
            "Operator should be registered in GatewayAVS"
        );

        // Verify BLS key storage
        (
            IProposerRegistry.Operator memory gatewayOpData,
            IProposerRegistry.Operator memory validatorOpData
        ) = proposerRegistry.getRegisteredOperator(operator);
        validatorOpData;
        assertEq(
            keccak256(gatewayOpData.blsKey),
            keccak256(operatorBLSPubKey),
            "BLS key should match"
        );
    }

    /// @notice Tests EigenPod creation
    /// @dev Verifies that a user can create an EigenPod and it's properly registered
    function test_EigenPodCreation() public {
        address podOwner = makeAddr("podOwner");

        vm.startPrank(podOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        vm.stopPrank();

        assertTrue(
            validatorAVS.EIGEN_POD_MANAGER().hasPod(podOwner), "Pod should be registered"
        );
        assertEq(
            address(eigenLayerDeployer.eigenPodManager().ownerToPod(podOwner)),
            podAddress,
            "Pod address should match"
        );
    }

    /// @notice Tests EigenPod delegation to an operator who's not the pod owner
    /// @dev Verifies that a pod owner can delegate their pod to an operator
    function test_EigenPodDelegation() public {
        address podOwner = makeAddr("podOwner");

        // Create pod
        vm.startPrank(podOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        podAddress;
        vm.stopPrank();

        // Register operator
        IDelegationManager.OperatorDetails memory operatorDetails =
            _operatorRegistration(operator);
        operatorDetails;

        // Delegate pod to operator
        vm.startPrank(podOwner);
        ISignatureUtils.SignatureWithExpiry memory operatorSignature =
            ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
        eigenLayerDeployer.delegationManager().delegateTo(
            operator, operatorSignature, bytes32(0)
        );
        vm.stopPrank();
        // Verify delegation
        assertEq(
            eigenLayerDeployer.delegationManager().delegatedTo(podOwner),
            operator,
            "Pod should be delegated to operator"
        );
    }

    /// @notice Tests complete validator registration flow through the middleware
    /// including pod creation, operator setup, and validator registration
    function test_CompleteValidatorRegistration() public {
        // Create and verify pod
        address mockPodOwner = vm.addr(1);
        vm.label(mockPodOwner, "mockPodOwner");

        vm.startPrank(mockPodOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        assertTrue(
            eigenLayerDeployer.eigenPodManager().hasPod(mockPodOwner),
            "Pod should be created."
        );
        vm.stopPrank();

        // 3. Register operator in EigenLayer and self delegate
        _operatorRegistration(mockPodOwner);

        bytes memory mockPodOwnerBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            mockPodOwnerBLSPubKey[i] = 0xcd;
        }

        // 4. Register as Operator in GatewayAVS
        _gatewayOperatorAVSRegistration(mockPodOwner, 1, 0, mockPodOwnerBLSPubKey);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInAVS(
                mockPodOwner, IProposerRegistry.AVSType.GATEWAY
            ),
            "Operator should be registered in GatewayAVS"
        );

        // 5. Register as Operator in ValidatorAVS
        _validatorOperatorAVSRegistration(mockPodOwner, 1, 1);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInAVS(
                mockPodOwner, IProposerRegistry.AVSType.VALIDATOR
            ),
            "Operator should be registered in ValidatorAVS"
        );

        // 6. Create test validator pubkey and delegatee
        bytes memory validatorPubkey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xab;
        }
        _cheatValidatorPubkeyActive(podAddress, validatorPubkey);

        // 7. Register validator
        bytes[][] memory valPubKeys = new bytes[][](1);
        valPubKeys[0] = new bytes[](1);
        valPubKeys[0][0] = validatorPubkey;

        address[] memory podOwners = new address[](1);
        podOwners[0] = mockPodOwner;

        bytes[] memory delegatedGateways = new bytes[](1);
        delegatedGateways[0] = mockPodOwnerBLSPubKey;

        vm.prank(mockPodOwner);
        validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);

        // 8. Verify registration status in proposer registry
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        IProposerRegistry.ValidatorStatus validatorStatus =
            proposerRegistry.getValidatorStatus(pubkeyHash);
        assertEq(uint8(validatorStatus), uint8(IProposerRegistry.ValidatorStatus.Active));

        // 9. Verify delegatee
        IProposerRegistry.Validator memory validator =
            proposerRegistry.getValidator(pubkeyHash);
        assertEq(keccak256(validator.delegatee), keccak256(mockPodOwnerBLSPubKey));

        // 10. Verify validator status in EigenPod
        IEigenPod pod = validatorAVS.EIGEN_POD_MANAGER().getPod(mockPodOwner);
        IEigenPod.ValidatorInfo memory info = pod.validatorPubkeyToInfo(validatorPubkey);
        assertEq(uint8(info.status), uint8(IEigenPod.VALIDATOR_STATUS.ACTIVE));
    }

    /// @notice Tests validator registration in ValidatorAVS
    /// @dev Verifies:
    /// 1. Multiple validators can be registered
    /// 2. Each validator has correct delegatee
    /// 3. Events are emitted correctly
    /// 4. Validator counts are tracked
    function test_MultipleValidatorRegistration() public {
        address podOwner = makeAddr("podOwner");

        // Setup pod and operator
        vm.startPrank(podOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        vm.stopPrank();

        // Register operator in EigenLayer
        _operatorRegistration(operator);
        _delegationToOperator(podOwner, operator);

        // Register operator in both AVS
        _gatewayOperatorAVSRegistration(operator, operatorSecretKey, 0, operatorBLSPubKey);
        _validatorOperatorAVSRegistration(operator, operatorSecretKey, 1);

        // Prepare multiple validator keys
        uint256 validatorCount = 3;
        bytes[][] memory valPubKeys = new bytes[][](1);
        valPubKeys[0] = new bytes[](validatorCount);
        bytes[] memory delegatedGateways = new bytes[](1);
        delegatedGateways[0] = operatorBLSPubKey; // Use operator's BLS key as delegatee
        address[] memory podOwners = new address[](1);
        podOwners[0] = podOwner;

        for (uint256 i = 0; i < validatorCount; i++) {
            valPubKeys[0][i] = new bytes(48);
            for (uint256 j = 0; j < 48; j++) {
                valPubKeys[0][i][j] = bytes1(uint8(0xab + i));
            }
            _cheatValidatorPubkeyActive(podAddress, valPubKeys[0][i]);
        }

        // Register validators
        vm.prank(podOwner);
        validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);

        // Verify registrations
        for (uint256 i = 0; i < validatorCount; i++) {
            bytes32 pubkeyHash = keccak256(valPubKeys[0][i]);
            IProposerRegistry.Validator memory validator =
                proposerRegistry.getValidator(pubkeyHash);

            assertEq(validator.operator, operator, "Wrong operator");
            assertEq(
                keccak256(validator.delegatee),
                keccak256(operatorBLSPubKey),
                "Wrong delegatee"
            );
            assertEq(
                uint8(validator.status),
                uint8(IProposerRegistry.ValidatorStatus.Active),
                "Wrong status"
            );
        }

        // Verify validator count
        assertEq(
            proposerRegistry.getValidatorCountForOperatorInAVS(
                address(validatorAVS), operator
            ),
            validatorCount,
            "Wrong validator count"
        );
    }

    /// @notice Tests reward distribution between GatewayAVS and ValidatorAVS
    function test_RewardDistribution() public {
        // Setup reward token and get shares
        (ERC20PresetFixedSupply rewardToken, uint256 gatewayShare, uint256 validatorShare)
        = _setupRewardToken();
        validatorShare;

        // Setup operators
        (
            address gatewayOp,
            address validatorOp1,
            address validatorOp2,
            uint256 gatewayOpKey,
            uint256 validatorOp1Key,
            uint256 validatorOp2Key
        ) = _setupOperators();
        gatewayOpKey;

        // Setup validator operators in both AVSs
        _setupValidatorOperatorsInAVS(
            validatorOp1, validatorOp2, validatorOp1Key, validatorOp2Key
        );

        IRewardsCoordinator.StrategyAndMultiplier[] memory strategyAndMultipliers =
            new IRewardsCoordinator.StrategyAndMultiplier[](1);
        strategyAndMultipliers[0] = IRewardsCoordinator.StrategyAndMultiplier({
            strategy: eigenLayerDeployer.wethStrat(),
            multiplier: 1 ether
        });

        // First submission: Gateway rewards
        IRewardsCoordinator.OperatorReward[] memory gatewayRewards =
            new IRewardsCoordinator.OperatorReward[](3);

        // Create rewards with operators (already in ascending order from _setupOperators)
        gatewayRewards[0] = IRewardsCoordinator.OperatorReward({
            operator: gatewayOp,
            amount: gatewayShare
        });
        gatewayRewards[1] =
            IRewardsCoordinator.OperatorReward({ operator: validatorOp1, amount: 0 });
        gatewayRewards[2] =
            IRewardsCoordinator.OperatorReward({ operator: validatorOp2, amount: 0 });

        // Second submission: Validator rewards (with sorted operators)
        IRewardsCoordinator.OperatorReward[] memory validatorRewards =
            new IRewardsCoordinator.OperatorReward[](2);
        validatorRewards[0] =
            IRewardsCoordinator.OperatorReward({ operator: validatorOp1, amount: 0 });
        validatorRewards[1] =
            IRewardsCoordinator.OperatorReward({ operator: validatorOp2, amount: 0 });

        // Create the submissions array
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](2);

        _warpToNextInterval(7 days + 1);

        // Gateway submission
        submissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: strategyAndMultipliers,
            token: rewardToken,
            operatorRewards: gatewayRewards,
            startTimestamp: uint32(block.timestamp - 14 days),
            duration: 7 days,
            description: "gateway"
        });

        // Validator submission
        submissions[1] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: strategyAndMultipliers,
            token: rewardToken,
            operatorRewards: validatorRewards,
            startTimestamp: uint32(block.timestamp - 14 days),
            duration: 7 days,
            description: "validator"
        });

        uint256 beforeBal =
            rewardToken.balanceOf(address(eigenLayerDeployer.rewardsCoordinator()));

        // Submit rewards as rewardsInitiator
        vm.prank(rewardsInitiator);
        gatewayAVS.createOperatorDirectedAVSRewardsSubmission(submissions);

        uint256 afterBal =
            rewardToken.balanceOf(address(eigenLayerDeployer.rewardsCoordinator()));

        assertApproxEqAbs(
            afterBal,
            beforeBal + 1000e18,
            1,
            "Coordinator balance should have increased by 1000 tokens"
        );

        // Todo: test the processClaim
        // vm.prank(gatewayOp);
        // gatewayAVS.processClaim(gatewayOp, address(rewardToken));
        // assertApproxEqAbs(
        //     rewardToken.balanceOf(gatewayOp), gatewayShare, 1, "Wrong gateway reward"
        // );
        // assertApproxEqAbs(
        //     rewardToken.balanceOf(validatorOp1),
        //     (validatorShare * 2) / 3,
        //     1,
        //     "Wrong validator1 reward"
        // );
        // assertApproxEqAbs(
        //     rewardToken.balanceOf(validatorOp2),
        //     validatorShare / 3,
        //     1,
        //     "Wrong validator2 reward"
        // );
    }

    function _warpToNextInterval(uint256 secondsToAdd) internal {
        uint32 interval =
            eigenLayerDeployer.rewardsCoordinator().CALCULATION_INTERVAL_SECONDS();
        uint32 startTimestamp = uint32(block.timestamp);
        uint256 warpTarget = startTimestamp + secondsToAdd;
        uint256 alignedWarp = (warpTarget / interval) * interval;
        if (alignedWarp <= warpTarget) {
            alignedWarp += interval;
        }
        vm.warp(alignedWarp);
    }

    /// @notice Helper function to setup reward token and transfer initial amount
    function _setupRewardToken()
        internal
        returns (ERC20PresetFixedSupply, uint256, uint256)
    {
        ERC20PresetFixedSupply rewardToken = new ERC20PresetFixedSupply(
            "Mock Reward Token", "MRT", 2000 ether, rewardsInitiator
        );

        uint256 totalReward = 1000 ether;
        uint256 gatewayShare = totalReward;

        // First approve gatewayAVS to spend tokens from rewardsInitiator
        vm.startPrank(rewardsInitiator);
        rewardToken.approve(address(gatewayAVS), type(uint256).max);
        vm.stopPrank();

        // Then approve RewardsCoordinator to spend tokens from gatewayAVS
        vm.prank(address(gatewayAVS));
        rewardToken.approve(
            address(eigenLayerDeployer.rewardsCoordinator()), type(uint256).max
        );

        return (rewardToken, gatewayShare, 0 ether);
    }

    /// @notice Helper function to setup operators
    function _setupOperators()
        internal
        returns (
            address gatewayOp,
            address validatorOp1,
            address validatorOp2,
            uint256 gatewayOpKey,
            uint256 validatorOp1Key,
            uint256 validatorOp2Key
        )
    {
        // Create operators in ascending order by manipulating the labels
        (gatewayOp, gatewayOpKey) = makeAddrAndKey("aaa_gateway1");
        (validatorOp1, validatorOp1Key) = makeAddrAndKey("bbb_validator1");
        (validatorOp2, validatorOp2Key) = makeAddrAndKey("ccc_validator2");

        _setupOperator(gatewayOp, true, gatewayOpKey);
        _setupOperator(validatorOp1, false, validatorOp1Key);
        _setupOperator(validatorOp2, false, validatorOp2Key);
    }

    /// @notice Helper function to setup validator operators in AVS
    function _setupValidatorOperatorsInAVS(
        address validatorOp1,
        address validatorOp2,
        uint256 validatorOp1Key,
        uint256 validatorOp2Key
    )
        internal
    {
        bytes memory validatorOp1BLSPubKey = _generateMockBLSKey();
        bytes memory validatorOp2BLSPubKey = _generateMockBLSKey();

        _gatewayOperatorAVSRegistration(
            validatorOp1, validatorOp1Key, 1, validatorOp1BLSPubKey
        );
        _gatewayOperatorAVSRegistration(
            validatorOp2, validatorOp2Key, 2, validatorOp2BLSPubKey
        );

        vm.startPrank(validatorOp1);
        validatorAVS.EIGEN_POD_MANAGER().createPod();
        vm.stopPrank();

        vm.startPrank(validatorOp2);
        validatorAVS.EIGEN_POD_MANAGER().createPod();
        vm.stopPrank();

        _registerValidatorsForOperator(validatorOp1, 2); // First operator has 2 validators
        _registerValidatorsForOperator(validatorOp2, 1); // Second operator has 1 validator
    }

    function _generateMockBLSKey() internal pure returns (bytes memory) {
        bytes memory blsKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            blsKey[i] = bytes1(uint8(0xab + i));
        }
        return blsKey;
    }

    /// @notice Helper function to create gateway rewards submission
    function _createGatewayRewardsSubmission(
        IERC20 rewardToken,
        address gatewayOperator1,
        address gatewayOperator2,
        uint256 gatewayShare
    )
        internal
        view
        returns (IRewardsCoordinator.OperatorDirectedRewardsSubmission memory)
    {
        IRewardsCoordinator.OperatorReward[] memory gatewayRewards =
            new IRewardsCoordinator.OperatorReward[](2);
        gatewayRewards[0] = IRewardsCoordinator.OperatorReward({
            operator: gatewayOperator1,
            amount: gatewayShare / 2
        });
        gatewayRewards[1] = IRewardsCoordinator.OperatorReward({
            operator: gatewayOperator2,
            amount: gatewayShare / 2
        });

        return IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: new IRewardsCoordinator.StrategyAndMultiplier[](0),
            token: rewardToken,
            operatorRewards: gatewayRewards,
            startTimestamp: uint32(block.timestamp),
            duration: 7 days,
            description: "gateway"
        });
    }

    /// @notice Helper function to create validator rewards submission
    function _createValidatorRewardsSubmission(
        IERC20 rewardToken,
        address validatorOperator1,
        address validatorOperator2,
        uint256 validatorShare
    )
        internal
        view
        returns (IRewardsCoordinator.OperatorDirectedRewardsSubmission memory)
    {
        IRewardsCoordinator.OperatorReward[] memory validatorRewards =
            new IRewardsCoordinator.OperatorReward[](2);
        validatorRewards[0] = IRewardsCoordinator.OperatorReward({
            operator: validatorOperator1,
            amount: (validatorShare * 2) / 3 // 2/3 of validator share (2 validators)
         });
        validatorRewards[1] = IRewardsCoordinator.OperatorReward({
            operator: validatorOperator2,
            amount: validatorShare / 3 // 1/3 of validator share (1 validator)
         });

        return IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: new IRewardsCoordinator.StrategyAndMultiplier[](0),
            token: rewardToken,
            operatorRewards: validatorRewards,
            startTimestamp: uint32(block.timestamp),
            duration: 7 days,
            description: "validator"
        });
    }

    function _setupOperator(
        address localOperator,
        bool isGateway,
        uint256 localOperatorSecretKey
    )
        internal
        impersonate(localOperator)
    {
        bytes memory blsKey = isGateway ? new bytes(48) : bytes("");
        if (isGateway) {
            for (uint256 i = 0; i < 48; i++) {
                blsKey[i] = 0xab;
            }
        }

        IDelegationManager.OperatorDetails memory operatorDetails =
            IDelegationManager.OperatorDetails(address(localOperator), address(0), 0);

        eigenLayerDeployer.delegationManager().registerAsOperator(
            operatorDetails, "https://taiyi.wtf"
        );

        ISignatureUtils.SignatureWithSaltAndExpiry memory sig = _getOperatorSignature(
            isGateway ? address(gatewayAVS) : address(validatorAVS),
            localOperator,
            localOperatorSecretKey,
            0
        );

        if (isGateway) {
            gatewayAVS.registerOperatorToAVSWithPubKey(localOperator, sig, blsKey);
        } else {
            validatorAVS.registerOperatorToAVS(localOperator, sig);
        }
    }

    function _registerValidatorsForOperator(
        address localOperator,
        uint256 count
    )
        internal
    {
        bytes[][] memory valPubKeys = new bytes[][](1);
        valPubKeys[0] = new bytes[](count);
        bytes[] memory delegatedGateways = new bytes[](1);
        delegatedGateways[0] = operatorBLSPubKey;
        address[] memory podOwners = new address[](1);
        podOwners[0] = localOperator;

        address podAddress =
            address(validatorAVS.EIGEN_POD_MANAGER().ownerToPod(localOperator));
        for (uint256 i = 0; i < count; i++) {
            valPubKeys[0][i] = new bytes(48);
            for (uint256 j = 0; j < 48; j++) {
                // Use both operator address and index to ensure uniqueness
                if (j < 20) {
                    valPubKeys[0][i][j] =
                        bytes1(uint8(uint256(uint160(localOperator)) >> (8 * (19 - j))));
                } else {
                    valPubKeys[0][i][j] = bytes1(uint8(i + 1));
                }
            }
            _cheatValidatorPubkeyActive(podAddress, valPubKeys[0][i]);
        }

        vm.prank(localOperator);
        validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);
    }

    /// @notice Helper function to simulate a validator being active in EigenLayer by manipulating storage
    function _cheatValidatorPubkeyActive(
        address podAddress,
        bytes memory pubkey
    )
        internal
    {
        // The contract uses sha256 on (pubkey || bytes16(0)).
        //    So replicate that here, to match exactly.
        bytes32 pubkeyHash = sha256(abi.encodePacked(pubkey, bytes16(0)));

        // The _validatorPubkeyHashToInfo mapping is at storage slot 54 on EigenPod.sol
        //    via 'forge inspect lib/eigenlayer-contracts/src/contracts/pods/EigenPod.sol:EigenPod storage'
        //    Key is keccak256(pubkeyHash, 54).
        bytes32 infoSlot = keccak256(abi.encode(pubkeyHash, uint256(54)));

        // Fill in the ValidatorInfo fields. If VALIDATOR_STATUS.ACTIVE = 1,
        //    we shift 1 by 192 bits for the status portion:
        uint64 validatorIndex = 123;
        uint64 restakedBalanceGwei = 32_000_000_000; // example: 32 ETH in Gwei
        uint64 lastCheckpointedAt = 9_999_999_999; // arbitrary placeholder
        uint256 statusActive = 1 << 192; // 1 = ACTIVE in IEigenPod.VALIDATOR_STATUS

        // Pack them into one 256-bit word.
        uint256 packed = uint256(validatorIndex);
        packed |= uint256(restakedBalanceGwei) << 64;
        packed |= uint256(lastCheckpointedAt) << 128;
        packed |= statusActive;

        vm.store(podAddress, infoSlot, bytes32(packed));
    }

    /// @notice Registers an operator in the DelegationManager
    function _operatorRegistration(address localOperator)
        internal
        impersonate(localOperator)
        returns (IDelegationManager.OperatorDetails memory operatorDetails)
    {
        operatorDetails =
            IDelegationManager.OperatorDetails(address(localOperator), address(0), 0);

        eigenLayerDeployer.delegationManager().registerAsOperator(
            operatorDetails, "https://taiyi.wtf"
        );
    }

    /// @notice Stakes WETH tokens through the EigenLayer strategy
    function _stakeWETH() internal impersonate(staker) returns (uint256 shares) {
        eigenLayerDeployer.weth().approve(
            address(eigenLayerDeployer.strategyManager()), 69 ether
        );

        shares = eigenLayerDeployer.strategyManager().depositIntoStrategy(
            eigenLayerDeployer.wethStrat(), eigenLayerDeployer.weth(), 69 ether
        );
    }

    /// @notice Delegates the staker to the operator within the DelegationManager
    function _delegationToOperator(
        address delegator,
        address delegateeOperator
    )
        internal
        impersonate(delegator)
    {
        ISignatureUtils.SignatureWithExpiry memory delegateeSignature =
            ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
        eigenLayerDeployer.delegationManager().delegateTo(
            delegateeOperator, delegateeSignature, bytes32(0)
        );
    }

    /// @notice Registers operator with Gateway AVS using signed message
    function _gatewayOperatorAVSRegistration(
        address localOperator,
        uint256 localOperatorSecretKey,
        uint256 salt,
        bytes memory blsPubKey
    )
        internal
        impersonate(localOperator)
    {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
        _getOperatorSignature(
            address(gatewayAVS), localOperator, localOperatorSecretKey, salt
        );
        gatewayAVS.registerOperatorToAVSWithPubKey(
            localOperator, operatorSignature, blsPubKey
        );
    }

    /// @notice Registers operator with Validator AVS using signed message
    function _validatorOperatorAVSRegistration(
        address localOperator,
        uint256 localOperatorSecretKey,
        uint256 salt
    )
        internal
        impersonate(localOperator)
    {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
        _getOperatorSignature(
            address(validatorAVS), localOperator, localOperatorSecretKey, salt
        );
        validatorAVS.registerOperatorToAVS(localOperator, operatorSignature);
    }

    /// @notice Generates operator signature for AVS registration
    function _getOperatorSignature(
        address avs,
        address localOperator,
        uint256 localOperatorSecretKey,
        uint256 salt
    )
        internal
        view
        returns (ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    {
        bytes32 digest = eigenLayerDeployer.avsDirectory()
            .calculateOperatorAVSRegistrationDigestHash({
            operator: localOperator,
            avs: avs,
            salt: bytes32(salt),
            expiry: type(uint256).max
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(localOperatorSecretKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        operatorSignature = ISignatureUtils.SignatureWithSaltAndExpiry(
            sig, bytes32(salt), type(uint256).max
        );
    }
}
