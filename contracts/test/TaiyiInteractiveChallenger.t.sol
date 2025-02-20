// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import { TaiyiInteractiveChallenger } from "../src/TaiyiInteractiveChallenger.sol";

import { TaiyiParameterManager } from "../src/TaiyiParameterManager.sol";
import { ITaiyiInteractiveChallenger } from
    "../src/interfaces/ITaiyiInteractiveChallenger.sol";

import { PreconfRequestAType } from "../src/types/PreconfRequestATypes.sol";
import {
    BlockspaceAllocation,
    PreconfRequestBType
} from "../src/types/PreconfRequestBTypes.sol";
import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { SP1Verifier } from "@sp1-contracts/v4.0.0-rc.3/SP1VerifierPlonk.sol";

contract TaiyiInteractiveChallengerTest is Test {
    address verifierAddress;
    address user;
    address owner;
    address signer;

    uint256 internal userPrivatekey;
    uint256 internal ownerPrivatekey;
    uint256 internal signerPrivatekey;

    TaiyiInteractiveChallenger taiyiInteractiveChallenger;

    function setUp() public {
        verifierAddress = address(new SP1Verifier());

        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");
        (signer, signerPrivatekey) = makeAddrAndKey("signer");

        TaiyiParameterManager parameterManager = new TaiyiParameterManager();
        parameterManager.initialize(owner, 1, 64, 256);

        taiyiInteractiveChallenger = new TaiyiInteractiveChallenger(
            owner, verifierAddress, bytes32(0), address(parameterManager)
        );
    }

    // =========================================
    //  Test: Create challenge AType
    // =========================================
    function testCreateChallengeATypeSuccess() public {
        bytes memory signature = new bytes(0);
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";

        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);

        vm.expectRevert("Not implemented");
        taiyiInteractiveChallenger.createChallengeAType(preconfRequestAType, signature);
    }

    // =========================================
    //  Test: Create challenge BType
    // =========================================
    function testCreateChallengeBTypeSuccess() public {
        bytes memory signature = new bytes(0);

        BlockspaceAllocation memory blockspaceAllocation = BlockspaceAllocation({
            gasLimit: 100_000,
            sender: 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb,
            recipient: 0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766,
            deposit: 1 ether,
            tip: 1 ether,
            targetSlot: 1,
            blobCount: 1
        });

        PreconfRequestBType memory preconfRequestBType = PreconfRequestBType({
            blockspaceAllocation: blockspaceAllocation,
            blockspaceAllocationSignature: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            gatewaySignedBlockspaceAllocation: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            rawTx: hex"53e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            gatewaySignedRawTx: hex"42e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c"
        });

        vm.expectRevert("Not implemented");
        taiyiInteractiveChallenger.createChallengeBType(preconfRequestBType, signature);
    }

    // =========================================
    // Test: Resolve expired challenge
    // =========================================
    function testResolveExpiredChallenge() public {
        bytes32 challengeId = keccak256(abi.encodePacked("challengeId"));
        vm.expectRevert("Not implemented");
        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);
    }

    // =========================================
    //  Test: Prove
    // =========================================
    function testProveSuccess() public {
        bytes32 challengeId = keccak256(abi.encodePacked("challengeId"));
        bytes memory proofValues = new bytes(0);
        bytes memory proofBytes = new bytes(0);

        vm.expectRevert();
        taiyiInteractiveChallenger.prove(challengeId, proofValues, proofBytes);
    }

    // =========================================
    //  Test: Get all challenges
    // =========================================
    function testGetChallenges() public {
        // TODO[Martin]: Add challenges to the contract
        ITaiyiInteractiveChallenger.Challenge[] memory challenges =
            taiyiInteractiveChallenger.getChallenges();
        assertEq(challenges.length, 0);
    }

    // =========================================
    //  Test: Get open challenges
    // =========================================
    function testGetOpenChallenges() public {
        // TODO[Martin]: Add challenges to the contract
        ITaiyiInteractiveChallenger.Challenge[] memory challenges =
            taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(challenges.length, 0);
    }

    // =========================================
    //  Test: Get challenge by id
    // =========================================
    function testGetChallengeById() public {
        bytes32 challengeId = keccak256(abi.encodePacked("challengeId"));
        vm.expectRevert("Not implemented");
        taiyiInteractiveChallenger.getChallenge(challengeId);
    }

    // =========================================
    //  Test: Owner can set verifier gateway
    // =========================================
    function testOwnerCanSetVerifierGateway() public {
        vm.prank(owner);
        taiyiInteractiveChallenger.setVerifierGateway(address(0x123));
        assertEq(taiyiInteractiveChallenger.verifierGateway(), address(0x123));
    }

    // =========================================
    //  Test: User is not authorized to set verifier gateway
    // =========================================
    function testUserCannotSetVerifierGateway() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiInteractiveChallenger.setVerifierGateway(address(0x123));
    }

    // =========================================
    // Test: Owner can set interactiveFraudProofVKey
    // =========================================
    function testOwnerCanSetInteractiveFraudProofVKey() public {
        vm.prank(owner);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(bytes32(0));
        assertEq(taiyiInteractiveChallenger.interactiveFraudProofVKey(), bytes32(0));
    }

    // =========================================
    // Test: User is not authorized to set interactiveFraudProofVKey
    // =========================================
    function testUserCannotSetInteractiveFraudProofVKey() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(bytes32(0));
    }
}
