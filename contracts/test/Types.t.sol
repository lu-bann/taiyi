// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/libs/PreconfRequestLib.sol";
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
            blockspaceAllocationSignature: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            gatewaySignedBlockspaceAllocation: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            rawTx: hex"53e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            gatewaySignedRawTx: hex"42e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c"
        });
        vm.chainId(1337);
        bytes32 preconfRequestBTypeHash = preconfRequestBType.getPreconfRequestBTypeHash();
        assertEq(
            preconfRequestBTypeHash,
            bytes32(0xf54edbcf22dd1a0ac4a7d2c87e9552d283df6141ccff486754dffa1820021ac1)
        );
    }
}
