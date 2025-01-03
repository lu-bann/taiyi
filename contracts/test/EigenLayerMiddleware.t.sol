// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IDelegationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import {ISignatureUtils} from "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import {EigenLayerMiddleware} from "src/EigenLayerMiddleware.sol";
import {TaiyiProposerRegistry} from "src/TaiyiProposerRegistry.sol";

import {EigenlayerDeployer} from "./utils/EigenlayerDeployer.sol";
import "forge-std/Test.sol";
import {BLS12381} from "src/libs/BLS12381.sol";

contract EigenlayerMiddlewareTest is Test {
    using BLS12381 for BLS12381.G1Point;

    EigenLayerMiddleware public eigenLayerMiddleware;
    TaiyiProposerRegistry public proposerRegistry;
    EigenlayerDeployer public eigenLayerDeployer;

    address public owner;
    address staker;
    address operator;
    uint256 operatorSecretKey;

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

        proposerRegistry = new TaiyiProposerRegistry();
        eigenLayerMiddleware = new EigenLayerMiddleware();

        vm.startPrank(owner);
        eigenLayerMiddleware.initialize(
            owner,
            address(proposerRegistry),
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager()),
            address(eigenLayerDeployer.strategyManager()),
            address(eigenLayerDeployer.eigenPodManager())
        );

        proposerRegistry.initialize(owner);
        proposerRegistry.addRestakingMiddlewareContract(address(eigenLayerMiddleware));
        vm.stopPrank();
    }

    // ============================================
    // ============= Test Functions ===============
    // ============================================

    function testOperatorRegistration() public {
        IDelegationManager.OperatorDetails memory operatorDetails = _operatorRegistration();
        assertEq(
            abi.encode(eigenLayerDeployer.delegationManager().operatorDetails(operator)), abi.encode(operatorDetails)
        );
    }

    function testStakeWETH() public {
        uint256 shares = _stakeWETH();
        assertEq(eigenLayerDeployer.wethStrat().sharesToUnderlyingView(shares), 69 ether);
    }

    function testStakerDelegationToOperator() public {
        IDelegationManager.OperatorDetails memory operatorDetails = _operatorRegistration();
        _stakerDelegationToOperator();
        assertEq(eigenLayerDeployer.delegationManager().delegatedTo(staker), operator);
    }

    function testOperatorAVSRegistration() public {
        _operatorRegistration();
        _operatorAVSRegistration();
        assertTrue(proposerRegistry.isOperatorRegistered(address(operator)), "Operator registration failed");
    }

    // ============================================
    // ============= Helper Functions =============
    // ============================================

    /// @notice Registers an operator in the DelegationManager
    function _operatorRegistration()
        internal
        impersonate(operator)
        returns (IDelegationManager.OperatorDetails memory operatorDetails)
    {
        operatorDetails = IDelegationManager.OperatorDetails(address(operator), address(0), 0);

        eigenLayerDeployer.delegationManager().registerAsOperator(operatorDetails, "https://taiyi.wtf");
    }

    /// @notice Stakes WETH tokens through the EigenLayer strategy
    function _stakeWETH() internal impersonate(staker) returns (uint256 shares) {
        eigenLayerDeployer.weth().approve(address(eigenLayerDeployer.strategyManager()), 69 ether);

        shares = eigenLayerDeployer.strategyManager().depositIntoStrategy(
            eigenLayerDeployer.wethStrat(), eigenLayerDeployer.weth(), 69 ether
        );
    }

    /// @notice Delegates the staker to the operator within the DelegationManager
    function _stakerDelegationToOperator() internal impersonate(staker) {
        ISignatureUtils.SignatureWithExpiry memory operatorSignature =
            ISignatureUtils.SignatureWithExpiry(bytes("signature"), 0);
        eigenLayerDeployer.delegationManager().delegateTo(operator, operatorSignature, bytes32(0));
    }

    /// @notice Registers operator with AVS using signed message
    function _operatorAVSRegistration() internal impersonate(operator) {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature = _getOperatorSignature();
        eigenLayerMiddleware.registerOperator(operatorSignature);
    }

    /// @notice Generates operator signature for AVS registration
    function _getOperatorSignature()
        internal
        returns (ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    {
        bytes32 digest = eigenLayerDeployer.avsDirectory().calculateOperatorAVSRegistrationDigestHash({
            operator: operator,
            avs: address(eigenLayerMiddleware),
            salt: bytes32(0),
            expiry: type(uint256).max
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorSecretKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        operatorSignature = ISignatureUtils.SignatureWithSaltAndExpiry(sig, bytes32(0), type(uint256).max);
    }
}
