// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

import { TaiyiProposerRegistry } from "src/TaiyiProposerRegistry.sol";
import { EigenLayerMiddleware } from "src/abstract/EigenLayerMiddleware.sol";

import { GatewayAVS } from "src/eigenlayer-avs/GatewayAVS.sol";
import { ValidatorAVS } from "src/eigenlayer-avs/ValidatorAVS.sol";
import { IProposerRegistry } from "src/interfaces/IProposerRegistry.sol";

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import "forge-std/Test.sol";
import { BLS12381 } from "src/libs/BLS12381.sol";

contract EigenlayerMiddlewareTest is Test {
    using BLS12381 for BLS12381.G1Point;

    EigenLayerMiddleware public eigenLayerMiddleware;
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

    // State variables
    BLS12381.G1Point internal operatorPublicKey;

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

    // ============================================
    // ============= Test Functions ===============
    // ============================================

    function testOperatorRegistration() public {
        IDelegationManager.OperatorDetails memory operatorDetails =
            _operatorRegistration();
        assertEq(
            abi.encode(eigenLayerDeployer.delegationManager().operatorDetails(operator)),
            abi.encode(operatorDetails)
        );
    }

    function testStakeWETH() public {
        uint256 shares = _stakeWETH();
        assertEq(eigenLayerDeployer.wethStrat().sharesToUnderlyingView(shares), 69 ether);
    }

    function testStakerDelegationToOperator() public {
        IDelegationManager.OperatorDetails memory operatorDetails =
            _operatorRegistration();
        _delegationToOperator(staker);
        assertEq(eigenLayerDeployer.delegationManager().delegatedTo(staker), operator);
    }

    function testGatewayOperatorAVSRegistration() public {
        _operatorRegistration();
        _gatewayOperatorAVSRegistration();
        assertTrue(
            proposerRegistry.isOperatorRegisteredInGatewayAVS(operator),
            "Gateway operator registration failed"
        );
    }

    function testValidatorOperatorAVSRegistration() public {
        _operatorRegistration();
        _validatorOperatorAVSRegistration();
        assertTrue(
            proposerRegistry.isOperatorRegisteredInValidatorAVS(operator),
            "Validator operator registration failed"
        );
    }

    /// @notice Tests creating an EigenPod and verifies successful creation
    function testCreatePod() public {
        address mockPodOwner = makeAddr("mockPodOwner");

        vm.startPrank(mockPodOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        vm.stopPrank();

        assertTrue(podAddress != address(0), "Pod should have been created");
    }

    /// @notice Tests complete validator registration flow through the middleware
    /// including pod creation, operator setup, and validator registration
    function testCompleteValidatorRegistrationFlow() public {
        address mockPodOwner = makeAddr("mockPodOwner");
        vm.startPrank(mockPodOwner);
        address podAddress = validatorAVS.EIGEN_POD_MANAGER().createPod();
        vm.stopPrank();

        // Set up operator and delegation
        _operatorRegistration();
        _delegationToOperator(mockPodOwner);
        _validatorOperatorAVSRegistration();

        // Create test validator pubkey and delegatee
        bytes memory validatorPubkey = new bytes(48);
        bytes memory delegatedGatewayPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            validatorPubkey[i] = 0xab;
            delegatedGatewayPubKey[i] = 0xcd;
        }
        _cheatValidatorPubkeyActive(podAddress, validatorPubkey);

        // Register validator
        bytes[][] memory valPubKeys = new bytes[][](1);
        valPubKeys[0] = new bytes[](1);
        valPubKeys[0][0] = validatorPubkey;

        address[] memory podOwners = new address[](1);
        podOwners[0] = mockPodOwner;

        bytes[] memory delegatedGateways = new bytes[](1);
        delegatedGateways[0] = delegatedGatewayPubKey;

        vm.prank(mockPodOwner);
        validatorAVS.registerValidators(valPubKeys, podOwners, delegatedGateways);

        // Verify registration status
        bytes32 pubkeyHash = keccak256(validatorPubkey);
        IProposerRegistry.ValidatorStatus validatorStatus =
            proposerRegistry.getValidatorStatus(pubkeyHash);
        assertEq(uint8(validatorStatus), uint8(IProposerRegistry.ValidatorStatus.Active));

        // Verify delegatee
        IProposerRegistry.Validator memory validator =
            proposerRegistry.getValidator(pubkeyHash);
        assertEq(keccak256(validator.delegatee), keccak256(delegatedGatewayPubKey));
    }

    // ============================================
    // ============= Helper Functions =============
    // ============================================

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
    function _operatorRegistration()
        internal
        impersonate(operator)
        returns (IDelegationManager.OperatorDetails memory operatorDetails)
    {
        operatorDetails =
            IDelegationManager.OperatorDetails(address(operator), address(0), 0);

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
    function _delegationToOperator(address delegator) internal impersonate(delegator) {
        ISignatureUtils.SignatureWithExpiry memory operatorSignature =
            ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
        eigenLayerDeployer.delegationManager().delegateTo(
            operator, operatorSignature, bytes32(0)
        );
    }

    /// @notice Registers operator with Gateway AVS using signed message
    function _gatewayOperatorAVSRegistration() internal impersonate(operator) {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _getOperatorSignature();
        gatewayAVS.registerOperatorToAVSWithPubKey(
            operator, operatorSignature, operatorBLSPubKey
        );
    }

    /// @notice Registers operator with Validator AVS using signed message
    function _validatorOperatorAVSRegistration() internal impersonate(operator) {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _getOperatorSignature();
        validatorAVS.registerOperatorToAVS(operator, operatorSignature);
    }

    /// @notice Generates operator signature for AVS registration
    function _getOperatorSignature()
        internal
        view
        returns (ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    {
        bytes32 digest = eigenLayerDeployer.avsDirectory()
            .calculateOperatorAVSRegistrationDigestHash({
            operator: operator,
            avs: address(validatorAVS),
            salt: bytes32(0),
            expiry: type(uint256).max
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorSecretKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        operatorSignature =
            ISignatureUtils.SignatureWithSaltAndExpiry(sig, bytes32(0), type(uint256).max);
    }
}
