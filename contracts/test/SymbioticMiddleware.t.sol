// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TaiyiRegistryCoordinator } from
    "../src/operator-registries/TaiyiRegistryCoordinator.sol";
import { SymbioticNetworkMiddleware } from
    "../src/symbiotic-network/SymbioticNetworkMiddleware.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { POCBaseTest } from "@symbiotic-test/POCBase.t.sol";

contract SymbioticMiddlewareTest is POCBaseTest {
    SymbioticNetworkMiddleware middleware;
    uint96 constant VALIDATOR_SUBNETWORK = 1;
    uint96 constant GATEWAY_SUBNETWORK = 2;
    TaiyiRegistryCoordinator registry;

    function setUp() public virtual override {
        address proxyAdmin = makeAddr("proxyAdmin");
        SYMBIOTIC_CORE_PROJECT_ROOT = "lib/middleware-sdk/lib/core/";
        super.setUp();

        // // Initialize core protocol components from POCBaseTest
        // _initializeCoreContracts();

        // TaiyiRegistryCoordinator registryImpl = new TaiyiRegistryCoordinator();
        // TransparentUpgradeableProxy registryProxy = new TransparentUpgradeableProxy(
        //     address(registryImpl),
        //     proxyAdmin, // Use proxyAdmin instead of owner
        //     abi.encodeWithSelector(
        //         TaiyiRegistryCoordinator.initialize.selector,
        //         owner,
        //         0,
        //         address(middleware)
        //     )
        // );
        // registry = TaiyiRegistryCoordinator(address(registryProxy));

        // SymbioticNetworkMiddleware middlewareImpl = new SymbioticNetworkMiddleware();

        // TransparentUpgradeableProxy middlewareProxy = new TransparentUpgradeableProxy(
        //     address(middlewareImpl),
        //     proxyAdmin,
        //     abi.encodeWithSelector(
        //         SymbioticNetworkMiddleware.initialize.selector,
        //         address(networkRegistry),
        //         1 days,
        //         address(vaultFactory),
        //         address(operatorRegistry),
        //         address(operatorNetworkOptInService),
        //         address(0),
        //         address(this),
        //         registry,
        //         1 days
        //     )
        // );

        // middleware = SymbioticNetworkMiddleware(address(middlewareProxy));

        // middleware.setupSubnetworks();

        // registry.setNetworkContracts(address(middleware));
    }

    function canCall(
        address caller,
        address target,
        bytes4 functionSig
    )
        external
        view
        returns (bool)
    {
        // Allow setupSubnetworks to be called by anyone during tests
        if (functionSig == bytes4(keccak256("setupSubnetworks()"))) {
            return true;
        }

        // For other functions, implement your normal logic
        return false;
    }

    function _initializeCoreContracts() internal {
        (vault1, delegator1, slasher1) =
            _getVaultAndNetworkRestakeDelegatorAndSlasher(7 days);
        (vault2, delegator2, slasher2) =
            _getVaultAndFullRestakeDelegatorAndSlasher(7 days);
    }

    function test_RegisterValidatorOperator() public {
        // Get validator operator
        address valOp = vm.addr(1);
        vm.label(valOp, "valOp");

        // Step 1: Register the operator in the operator registry
        vm.startPrank(valOp);
        operatorRegistry.registerOperator();
        vm.stopPrank();

        // Step 2: Register the middleware as a network in the network registry
        vm.startPrank(address(middleware));
        networkRegistry.registerNetwork();
        vm.stopPrank();

        // Step 3: The network registry needs to register itself as an entity
        vm.startPrank(address(networkRegistry));
        networkRegistry.registerNetwork();
        vm.stopPrank();

        // Step 4: Operator opts into both the network registry and middleware
        vm.startPrank(valOp);
        operatorNetworkOptInService.optIn(address(networkRegistry));
        operatorNetworkOptInService.optIn(address(middleware));
        vm.stopPrank();

        // Step 5: Register the operator with the middleware
        // The verification will pass as the key contains the operator address
        bytes memory key = abi.encode(valOp);
        bytes memory signature = "";
        address vault = address(0);
        uint96 subnetwork = 1; // VALIDATOR_SUBNETWORK = 1

        vm.startPrank(valOp);
        middleware.registerOperator(key, vault, signature, subnetwork);
        vm.stopPrank();
    }
}
