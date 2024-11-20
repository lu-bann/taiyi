// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../src/TaiyiDelegation.sol";
import "../src/TaiyiProposerRegistry.sol";

contract TaiyiDelegationTest is Test {
    TaiyiDelegation public delegation;
    IProposerRegistry public mockRegistry;

    address constant registrar = address(0x456);
    address constant Preconfer = address(0x123);
    bytes32 constant mockValidatorPubKeyHash = bytes32(uint256(1));

    function setUp() public {
        mockRegistry = new TaiyiProposerRegistry();
        delegation = new TaiyiDelegation(address(mockRegistry));

        vm.prank(address(this));
        delegation.registerPreconfer(Preconfer);
    }

    function testRegisterPreconfer() public {
        address newPreconfer = address(0x789);
        delegation.registerPreconfer(newPreconfer);
        assertTrue(delegation.isRegisteredPreconfer(newPreconfer));
    }

    function testDeregisterPreconfer() public {
        delegation.deregisterPreconfer(Preconfer);
        assertFalse(delegation.isRegisteredPreconfer(Preconfer));
    }

    function testDelegatePreconfDuty() public {
        bytes memory pubkey = hex"8b91b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

        bytes32 validatorHash = delegation.hashBLSPubKey(pubkey);

        // Register validator in registry
        vm.prank(registrar);
        TaiyiProposerRegistry(address(mockRegistry)).registerValidator(pubkey);

        // Create delegation request
        TaiyiDelegation.PreconferElection memory election = IDelegationContract.PreconferElection({
            validatorPubkey: pubkey,
            preconferAddress: Preconfer,
            chainId: 1,
            preconferPubkey: pubkey
        });

        // Execute delegation
        vm.prank(registrar);
        delegation.delegatePreconfDuty(election);

        // Verify delegation was recorded
        assertEq(delegation.getDelegatedPreconfer(validatorHash), Preconfer);
    }

    function testRevokeDelegation() public {
        // Setup validator in registry
        bytes memory pubkey = hex"8b91b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

        // Calculate hash using the same function as in TaiyiDelegation
        bytes32 validatorHash = delegation.hashBLSPubKey(pubkey);

        // Register validator in registry
        vm.prank(registrar);
        TaiyiProposerRegistry(address(mockRegistry)).registerValidator(pubkey);

        TaiyiDelegation.PreconferElection memory election = IDelegationContract.PreconferElection({
            validatorPubkey: pubkey,
            preconferAddress: Preconfer,
            chainId: 1,
            preconferPubkey: pubkey
        });

        vm.prank(registrar);
        delegation.delegatePreconfDuty(election);

        assertEq(delegation.getDelegatedPreconfer(validatorHash), Preconfer);

        vm.warp(block.timestamp + delegation.DELEGATION_CHANGE_COOLDOWN() + 1);

        // Now revoke the delegation
        vm.prank(registrar);
        delegation.revokeDelegation(validatorHash);

        // Verify delegation was revoked
        assertEq(delegation.getDelegatedPreconfer(validatorHash), address(0));
    }
}
