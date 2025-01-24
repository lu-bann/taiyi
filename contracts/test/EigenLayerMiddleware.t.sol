// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
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
        rewardsInitiator = makeAddr("rewardsInitiator");

        // Create mock BLS key
        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }

        proposerRegistry = new TaiyiProposerRegistry();
        validatorAVS = new ValidatorAVS();
        gatewayAVS = new GatewayAVS();

        vm.startPrank(owner);

        proposerRegistry.initialize(owner);

        // Initialize GatewayAVS
        gatewayAVS.initializeGatewayAVS(
            owner,
            address(proposerRegistry),
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager()),
            address(eigenLayerDeployer.strategyManager()),
            address(eigenLayerDeployer.eigenPodManager()),
            address(eigenLayerDeployer.rewardsCoordinator()),
            rewardsInitiator
        );

        // Initialize ValidatorAVS
        validatorAVS.initializeValidatorAVS(
            owner,
            address(proposerRegistry),
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager()),
            address(eigenLayerDeployer.strategyManager()),
            address(eigenLayerDeployer.eigenPodManager()),
            address(eigenLayerDeployer.rewardsCoordinator()),
            rewardsInitiator
        );

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
        _operatorRegistration(operator);
        _gatewayOperatorAVSRegistration(operator, operatorBLSPubKey);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInGatewayAVS(operator),
            "Gateway operator registration failed"
        );
    }

    function testValidatorOperatorAVSRegistration() public {
        _operatorRegistration(operator);
        _validatorOperatorAVSRegistration(operator);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInValidatorAVS(operator),
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

        vm.prank(operator);
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _getOperatorSignature(address(gatewayAVS));
        gatewayAVS.registerOperatorToAVSWithPubKey(
            operator, operatorSignature, operatorBLSPubKey
        );

        // Verify registration
        assertTrue(
            proposerRegistry.isOperatorRegisteredInGatewayAVS(operator),
            "Operator should be registered in GatewayAVS"
        );

        // Verify BLS key storage
        IProposerRegistry.Operator memory opData =
            proposerRegistry.getRegisteredOperator(operator);
        assertEq(
            keccak256(opData.blsKey), keccak256(operatorBLSPubKey), "BLS key should match"
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

    /// @notice Tests EigenPod delegation to an operator
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
        vm.prank(podOwner);
        ISignatureUtils.SignatureWithExpiry memory operatorSignature =
            ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
        eigenLayerDeployer.delegationManager().delegateTo(
            operator, operatorSignature, bytes32(0)
        );

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
        // 1. Prepare addresses & keys
        address mockPodOwner;
        uint256 mockPodOwnerKey;
        (mockPodOwner, mockPodOwnerKey) = makeAddrAndKey("mockPodOwner");

        // 2. Create pod
        vm.startPrank(mockPodOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        assertTrue(
            eigenLayerDeployer.eigenPodManager().hasPod(mockPodOwner),
            "Pod should be created."
        );
        vm.stopPrank();

        // 3. Register operator in EigenLayer
        _operatorRegistration(mockPodOwner);

        // 4. Register as Operator in GatewayAVS
        bytes memory mockPodOwnerBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            mockPodOwnerBLSPubKey[i] = 0xcd;
        }
        _gatewayOperatorAVSRegistration(mockPodOwner, mockPodOwnerBLSPubKey);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInGatewayAVS(mockPodOwner),
            "Operator should be registered in GatewayAVS"
        );

        // 5. Register as Operator in ValidatorAVS
        _validatorOperatorAVSRegistration(mockPodOwner);
        assertTrue(
            proposerRegistry.isOperatorRegisteredInValidatorAVS(mockPodOwner),
            "Operator should be registered in ValidatorAVS"
        );

        // 6. Self delegate
        _delegationToOperator(mockPodOwner, mockPodOwner);
        assertTrue(
            eigenLayerDeployer.delegationManager().isOperator(mockPodOwner),
            "Should be operator."
        );
        assertEq(
            eigenLayerDeployer.delegationManager().delegatedTo(mockPodOwner),
            mockPodOwner,
            "Should be self-delegated."
        );

        // 7. Create test validator pubkey and delegatee
        bytes memory validatorPubkey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xab;
        }
        _cheatValidatorPubkeyActive(podAddress, validatorPubkey);

        // 8. Register validator
        bytes[][] memory valPubKeys = new bytes[][](1);
        valPubKeys[0] = new bytes[](1);
        valPubKeys[0][0] = validatorPubkey;

        address[] memory podOwners = new address[](1);
        podOwners[0] = mockPodOwner;

        bytes[] memory delegatedGateways = new bytes[](1);
        delegatedGateways[0] = mockPodOwnerBLSPubKey;

        vm.prank(mockPodOwner);
        validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);

        // 9. Verify registration status
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        IProposerRegistry.ValidatorStatus validatorStatus =
            proposerRegistry.getValidatorStatus(pubkeyHash);
        assertEq(uint8(validatorStatus), uint8(IProposerRegistry.ValidatorStatus.Active));

        // Verify delegatee
        IProposerRegistry.Validator memory validator =
            proposerRegistry.getValidator(pubkeyHash);
        assertEq(keccak256(validator.delegatee), keccak256(mockPodOwnerBLSPubKey));
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

        _operatorRegistration(operator);
        _delegationToOperator(podOwner, operator);

        // Register operator in ValidatorAVS
        vm.startPrank(operator);
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _getOperatorSignature(address(validatorAVS));
        validatorAVS.registerOperatorToAVS(operator, operatorSignature);
        vm.stopPrank();

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
    /// @dev Verifies:
    /// 1. Rewards are split correctly between Gateway (80%) and Validator (20%)
    /// 2. Gateway rewards are distributed evenly among gateway operators
    /// 3. Validator rewards are distributed proportionally to validator count
    /// @dev Following the comment in GatewayAVS.sol:
    function test_RewardDistribution() public {
        // Setup test tokens and amounts
        IERC20 rewardToken = IERC20(makeAddr("rewardToken"));
        uint256 totalReward = 1000 ether;
        uint256 gatewayShare = (totalReward * GATEWAY_SHARE_BIPS) / 10_000; // 80%
        uint256 validatorShare = totalReward - gatewayShare; // 20%

        // Setup mock token
        deal(address(rewardToken), address(this), totalReward);
        deal(address(rewardToken), address(gatewayAVS), totalReward);

        // Setup operators
        address gatewayOperator1 = makeAddr("gateway1");
        address gatewayOperator2 = makeAddr("gateway2");
        address validatorOperator1 = makeAddr("validator1");
        address validatorOperator2 = makeAddr("validator2");

        // Register operators
        vm.startPrank(owner);
        _setupOperator(gatewayOperator1, true); // Gateway operator
        _setupOperator(gatewayOperator2, true); // Gateway operator
        _setupOperator(validatorOperator1, false); // Validator operator
        _setupOperator(validatorOperator2, false); // Validator operator
        vm.stopPrank();

        // Register validators for validator operators
        // validator1 has 2 validators, validator2 has 1 validator
        _registerValidatorsForOperator(validatorOperator1, 2);
        _registerValidatorsForOperator(validatorOperator2, 1);

        // Create reward submissions
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](2);

        // Gateway submission
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

        submissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: new IRewardsCoordinator.StrategyAndMultiplier[](0),
            token: rewardToken,
            operatorRewards: gatewayRewards,
            startTimestamp: uint32(block.timestamp),
            duration: 7 days,
            description: "gateway"
        });

        // Validator submission
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

        submissions[1] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: new IRewardsCoordinator.StrategyAndMultiplier[](0),
            token: rewardToken,
            operatorRewards: validatorRewards,
            startTimestamp: uint32(block.timestamp),
            duration: 7 days,
            description: "validator"
        });

        // Distribute rewards
        vm.prank(rewardsInitiator);
        gatewayAVS.createOperatorDirectedAVSRewardsSubmission(submissions);

        // Verify reward distribution
        // Gateway operators should each get 50% of gateway share
        assertApproxEqAbs(
            rewardToken.balanceOf(gatewayOperator1),
            gatewayShare / 2,
            1,
            "Wrong gateway1 reward"
        );
        assertApproxEqAbs(
            rewardToken.balanceOf(gatewayOperator2),
            gatewayShare / 2,
            1,
            "Wrong gateway2 reward"
        );

        // Validator operators should get proportional to validator count
        assertApproxEqAbs(
            rewardToken.balanceOf(validatorOperator1),
            (validatorShare * 2) / 3,
            1,
            "Wrong validator1 reward"
        );
        assertApproxEqAbs(
            rewardToken.balanceOf(validatorOperator2),
            validatorShare / 3,
            1,
            "Wrong validator2 reward"
        );
    }

    function _setupOperator(address localOperator, bool isGateway) internal {
        bytes memory blsKey = isGateway ? new bytes(48) : bytes("");
        if (isGateway) {
            for (uint256 i = 0; i < 48; i++) {
                blsKey[i] = 0xab;
            }
        }

        vm.prank(localOperator);
        IDelegationManager.OperatorDetails memory details =
            IDelegationManager.OperatorDetails(localOperator, address(0), 0);
        eigenLayerDeployer.delegationManager().registerAsOperator(
            details, "https://taiyi.wtf"
        );

        ISignatureUtils.SignatureWithSaltAndExpiry memory sig =
            _getOperatorSignature(isGateway ? address(gatewayAVS) : address(validatorAVS));

        if (isGateway) {
            vm.prank(localOperator);
            gatewayAVS.registerOperatorToAVSWithPubKey(localOperator, sig, blsKey);
        } else {
            vm.prank(localOperator);
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
                valPubKeys[0][i][j] = bytes1(uint8(0xab + i));
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
        bytes memory blsPubKey
    )
        internal
        impersonate(localOperator)
    {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _getOperatorSignature(address(gatewayAVS));
        gatewayAVS.registerOperatorToAVSWithPubKey(
            localOperator, operatorSignature, blsPubKey
        );
    }

    /// @notice Registers operator with Validator AVS using signed message
    function _validatorOperatorAVSRegistration(address localOperator)
        internal
        impersonate(localOperator)
    {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _getOperatorSignature(address(validatorAVS));
        validatorAVS.registerOperatorToAVS(localOperator, operatorSignature);
    }

    /// @notice Generates operator signature for AVS registration
    function _getOperatorSignature(address avs)
        internal
        view
        returns (ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    {
        bytes32 digest = eigenLayerDeployer.avsDirectory()
            .calculateOperatorAVSRegistrationDigestHash({
            operator: operator,
            avs: avs,
            salt: bytes32(0),
            expiry: type(uint256).max
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorSecretKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        operatorSignature =
            ISignatureUtils.SignatureWithSaltAndExpiry(sig, bytes32(0), type(uint256).max);
    }
}
