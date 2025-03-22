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

    uint256 internal SEPOLIA_GENESIS_TIMESTAMP = 1_655_733_600;

    TaiyiInteractiveChallenger taiyiInteractiveChallenger;
    TaiyiParameterManager parameterManager;

    function setUp() public {
        verifierAddress = address(new SP1Verifier());

        // Create test accounts
        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");
        (signer, signerPrivatekey) = makeAddrAndKey("signer");

        // Fund test accounts
        vm.deal(user, 100 ether);
        vm.deal(owner, 100 ether);
        vm.deal(signer, 100 ether);

        parameterManager = new TaiyiParameterManager();
        parameterManager.initialize(owner, 1, 64, 256, SEPOLIA_GENESIS_TIMESTAMP, 12);

        taiyiInteractiveChallenger = new TaiyiInteractiveChallenger(
            owner, verifierAddress, bytes32(0), address(parameterManager)
        );
    }

    // =========================================
    //  Test: Create challenge AType
    // =========================================
    function testCreateChallengeAType() public {
        // Send transaction as user
        vm.startPrank(user);

        // TODO[Martin]: Use real tx data
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";
        uint256 bond = parameterManager.challengeBond();

        // Create and sign preconf request
        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, challengeId);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect event
        vm.expectEmit(true, true, true, false);
        emit ITaiyiInteractiveChallenger.ChallengeOpened(challengeId, user, signer);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Fails to create challenge AType with invalid bond
    // =========================================
    function testCreateChallengeATypeFailsWithInvalidBond() public {
        // Send transaction as user
        vm.startPrank(user);

        bytes memory signature = new bytes(0);
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";

        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeBondInvalid.selector);
        taiyiInteractiveChallenger.createChallengeAType(preconfRequestAType, signature);

        vm.stopPrank();
    }

    // =========================================
    //  Test: Fails to create challenge AType with challenge already exists
    // =========================================
    function testCreateChallengeATypeFailsChallengeAlreadyExists() public {
        // Send transaction as user
        vm.startPrank(user);

        // TODO[Martin]: Use real tx data
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";
        uint256 bond = parameterManager.challengeBond();

        // Create and sign preconf request
        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, challengeId);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create challenge
        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.expectRevert(ITaiyiInteractiveChallenger.ChallengeAlreadyExists.selector);

        // Try to create the same challenge again
        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // TODO: Implement with concreate (real) data
    // =========================================
    //  Test: Create challenge BType
    // =========================================
    // function testCreateChallengeBType() public {
    //     uint256 bond = parameterManager.challengeBond();

    //     BlockspaceAllocation memory blockspaceAllocation = BlockspaceAllocation({
    //         gasLimit: 100_000,
    //         sender: 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb,
    //         recipient: 0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766,
    //         deposit: 1 ether,
    //         tip: 1 ether,
    //         targetSlot: vm.getBlockNumber(),
    //         blobCount: 1
    //     });

    //     PreconfRequestBType memory preconfRequestBType = PreconfRequestBType({
    //         blockspaceAllocation: blockspaceAllocation,
    //         blockspaceAllocationSignature: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
    //         gatewaySignedBlockspaceAllocation: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
    //         rawTx: hex"53e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
    //         gatewaySignedRawTx: hex"42e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c"
    //     });

    //     bytes32 dataHash = keccak256(abi.encode(
    //         blockspaceAllocation,
    //         preconfRequestBType.gatewaySignedRawTx
    //     ));

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, dataHash);
    //     bytes memory signature = abi.encodePacked(r, s, v);

    //     taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
    //         preconfRequestBType, signature
    //     );
    // }

    // =========================================
    //  Test: Fails to create challenge BType with invalid bond
    // =========================================
    function testCreateChallengeBTypeFailsWithInvalidBond() public {
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

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeBondInvalid.selector);
        taiyiInteractiveChallenger.createChallengeBType(preconfRequestBType, signature);
    }

    // =========================================
    // Test: Resolve expired challenge
    // =========================================
    function testResolveExpiredChallenge() public {
        // Send transaction as user
        vm.startPrank(user);

        // TODO[Martin]: Use real tx data
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";
        uint256 bond = parameterManager.challengeBond();

        // Create and sign preconf request
        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, challengeId);
        bytes memory signature = abi.encodePacked(r, s, v);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        // Skip duration so the challenge is expired
        skip(parameterManager.challengeMaxDuration() + 1);

        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge fails with challenge not expired
    // =========================================
    function testResolveExpiredChallengeFailsWithNotExpired() public {
        // Send transaction as user
        vm.startPrank(user);

        // TODO[Martin]: Use real tx data
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";
        uint256 bond = parameterManager.challengeBond();

        // Create and sign preconf request
        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, challengeId);
        bytes memory signature = abi.encodePacked(r, s, v);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeNotExpired.selector);

        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge fails with challenge does not exist
    // =========================================
    function testResolveExpiredChallengeFailsWithDoesNotExist() public {
        // Send transaction as user
        vm.startPrank(user);

        // TODO[Martin]: Use real tx data
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";
        uint256 bond = parameterManager.challengeBond();

        // Create and sign preconf request
        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, challengeId);
        bytes memory signature = abi.encodePacked(r, s, v);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeDoesNotExist.selector);

        taiyiInteractiveChallenger.resolveExpiredChallenge(
            keccak256("randomInvalidChallengeId")
        );

        vm.stopPrank();
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
        vm.startPrank(user);

        // TODO[Martin]: Use real tx data
        bytes[] memory txs = new bytes[](1);
        bytes memory tipTx = hex"01";
        uint256 bond = parameterManager.challengeBond();

        // Create and sign preconf request
        PreconfRequestAType memory preconfRequestAType =
            PreconfRequestAType(txs, tipTx, 0, 0, signer);
        bytes memory encodedPreconfRequestAType = abi.encode(preconfRequestAType);
        bytes32 challengeId = keccak256(encodedPreconfRequestAType);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivatekey, challengeId);
        bytes memory signature = abi.encodePacked(r, s, v);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        ITaiyiInteractiveChallenger.Challenge memory challenge =
            taiyiInteractiveChallenger.getChallenge(challengeId);

        assertEq(challenge.id, challengeId);
        // TODO[Martin]: Check challenge.createdAt
        assertEq(challenge.challenger, user);
        assertEq(challenge.commitmentSigner, signer);
        assertTrue(challenge.status == ITaiyiInteractiveChallenger.ChallengeStatus.Open);
        assertEq(challenge.preconfType, 0);
        assertEq(challenge.commitmentData, encodedPreconfRequestAType);
        assertEq(challenge.signature, signature);

        vm.stopPrank();
    }

    // =========================================
    //  Test: Get challenge by id fails with challenge does not exist
    // =========================================
    function testGetChallengeByIdFailsWithDoesNotExist() public {
        bytes32 challengeId = keccak256(abi.encodePacked("challengeId"));
        vm.expectRevert(ITaiyiInteractiveChallenger.ChallengeDoesNotExist.selector);
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
