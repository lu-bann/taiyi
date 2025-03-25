// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/TaiyiProposerRegistry.sol";

import "../src/libs/PreconfRequestLib.sol";
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

    function testPreconfRequestHash() public {
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
            bytes32(0xf6aa7a95c590ae41f6b0e513a6c827bc6a7e23df2f5cd54a7bb84419cfaddfad)
        );
    }
}
