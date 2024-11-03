// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../src/TaiyiDelegation.sol";
import "../src/TaiyiProposerRegistry.sol";

contract TaiyiDelegationTest is Test {
    TaiyiDelegation public delegation;
    IProposerRegistry public mockRegistry;

    address constant registrar = address(0x456);
    address constant preconfirmer = address(0x123);
    bytes32 constant mockValidatorPubKeyHash = bytes32(uint256(1));

    function setUp() public {
        mockRegistry = new TaiyiProposerRegistry();
        delegation = new TaiyiDelegation(address(mockRegistry));

        vm.prank(address(this));
        delegation.registerPreconfirmer(preconfirmer);
    }

    function testRegisterPreconfirmer() public {
        address newPreconfirmer = address(0x789);
        delegation.registerPreconfirmer(newPreconfirmer);
        assertTrue(delegation.isRegisteredPreconfirmer(newPreconfirmer));
    }

    function testDeregisterPreconfirmer() public {
        delegation.deregisterPreconfirmer(preconfirmer);
        assertFalse(delegation.isRegisteredPreconfirmer(preconfirmer));
    }

    function testDelegatePreconfDuty() public {
        bytes memory pubkey = hex"8b91b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

        bytes32 validatorHash = delegation.hashBLSPubKey(pubkey);

        // Register validator in registry
        vm.prank(registrar);
        TaiyiProposerRegistry(address(mockRegistry)).registerValidator(
            pubkey,
            // block.timestamp + 1 days,
            // BLS12381.G2Point({
            //     x: [uint256(0), uint256(0)],
            //     x_I: [uint256(0), uint256(0)],
            //     y: [uint256(0), uint256(0)],
            //     y_I: [uint256(0), uint256(0)]
            // }),
            address(0)
        );

        // Create delegation request
        TaiyiDelegation.PreconferElection memory election = IDelegationContract.PreconferElection({
            validatorPubkey: pubkey,
            preconferAddress: preconfirmer,
            chainId: 1,
            preconferPubkey: pubkey
        });

        // Execute delegation
        vm.prank(registrar);
        delegation.delegatePreconfDuty(election);

        // Verify delegation was recorded
        assertEq(delegation.getDelegatedPreconfirmer(validatorHash), preconfirmer);
    }

    function testRevokeDelegation() public {
        // Setup validator in registry
        bytes memory pubkey = hex"8b91b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

        // Calculate hash using the same function as in TaiyiDelegation
        bytes32 validatorHash = delegation.hashBLSPubKey(pubkey);

        // Register validator in registry
        vm.prank(registrar);
        TaiyiProposerRegistry(address(mockRegistry)).registerValidator(pubkey, address(0));

        TaiyiDelegation.PreconferElection memory election = IDelegationContract.PreconferElection({
            validatorPubkey: pubkey,
            preconferAddress: preconfirmer,
            chainId: 1,
            preconferPubkey: pubkey
        });

        vm.prank(registrar);
        delegation.delegatePreconfDuty(election);

        assertEq(delegation.getDelegatedPreconfirmer(validatorHash), preconfirmer);

        vm.warp(block.timestamp + delegation.DELEGATION_CHANGE_COOLDOWN() + 1);

        // Now revoke the delegation
        vm.prank(registrar);
        delegation.revokeDelegation(validatorHash);

        // Verify delegation was revoked
        assertEq(delegation.getDelegatedPreconfirmer(validatorHash), address(0));
    }
}
