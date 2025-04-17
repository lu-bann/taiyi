// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/TaiyiProposerRegistry.sol";

import "../src/libs/PreconfRequestLib.sol";
import "../src/types/PreconfRequestATypes.sol";
import "../src/types/PreconfRequestBTypes.sol";
import "../src/utils/Helper.sol";
import "forge-std/Test.sol";

contract PreconTxTest is Test {
    using PreconfRequestLib for *;
    using Helper for bytes;

    address user;
    address owner;
    uint256 userPrivatekey;
    uint256 ownerPrivatekey;

    bytes rawTx =
        hex"000000000000000000000000a83114a443da1cecefc50368531cace9f37fcccb0000000000000000000000006d2e03b7effeae98bd302a9f836d0d6ab000276600000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000005208000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000011100000000000000000000000000000000000000000000000000000000000000";

    function setUp() public {
        (user, userPrivatekey) = makeAddrAndKey("user");
        (owner, ownerPrivatekey) = makeAddrAndKey("owner");
    }

    function testPreconfRequestHashPreconfRequestAType() public {
        string[] memory txs = new string[](1);
        txs[0] = "txs";

        PreconfRequestAType memory preconfRequestAType = PreconfRequestAType({
            tipTx: "tipTx",
            txs: txs,
            slot: 1,
            sequenceNum: 1,
            signer: 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb
        });
        bytes32 preconfRequestATypeHash = preconfRequestAType.getPreconfRequestATypeHash();
        assertEq(
            preconfRequestATypeHash,
            bytes32(0x9c7db1b36cb7e7a7dc42c4a03d2fae8a7ef43df867cbd588949c1b12bd655b2a)
        );
    }

    function testPreconfRequestHashPreconfRequestBType() public {
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
            blockspaceAllocationSignature: bytes("blockspaceAllocationSignature"),
            underwriterSignedBlockspaceAllocation: bytes(
                "underwriterSignedBlockspaceAllocation"
            ),
            rawTx: bytes("rawTx"),
            underwriterSignedRawTx: bytes("underwriterSignedRawTx")
        });
        vm.chainId(1337);
        bytes32 preconfRequestBTypeHash = preconfRequestBType.getPreconfRequestBTypeHash();
        assertEq(
            preconfRequestBTypeHash,
            bytes32(0x47587e59c3c292d44165684296207000aa23e9113f858cf7858b202c52afe959)
        );
    }
}
