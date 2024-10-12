// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../src/TaiyiProposerRegistry.sol";
import "../src/interfaces/Types.sol";
import "../src/libs/PreconfRequestLib.sol";

contract PreconTxTest is Test {
    using PreconfRequestLib for PreconfTx;
    using PreconfRequestLib for TipTx;

    function setUp() public { }

    function testPreconTxHash() public pure {
        PreconfTx memory preconfTx = PreconfTx({
            from: 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb,
            to: 0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766,
            value: 1000,
            callData: hex"11",
            callGasLimit: 21_000,
            nonce: 1,
            signature: ""
        });

        bytes32 hash = preconfTx.getPreconfTxHash();

        bytes memory encoded = preconfTx.encodePreconfTx();
        assertEq(
            encoded,
            hex"000000000000000000000000a83114a443da1cecefc50368531cace9f37fcccb0000000000000000000000006d2e03b7effeae98bd302a9f836d0d6ab000276600000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000005208000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000011100000000000000000000000000000000000000000000000000000000000000"
        );
        assertEq(hash, bytes32(0x7b61576a8d5323483fd3f578d0adbb469bb77d6674278aeb8550231c0a6e8ff9));
    }

    function testPreconTxEmptyCalldataHash() public pure {
        PreconfTx memory preconfTx = PreconfTx({
            from: 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb,
            to: 0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766,
            value: 1000,
            callData: "",
            callGasLimit: 21_000,
            nonce: 1,
            signature: ""
        });

        bytes32 hash = preconfTx.getPreconfTxHash();

        assertEq(hash, bytes32(0x5db8eee818de95bee126e27f278d765b7ef486865e46395e991b8527be726c7d));
    }

    function testTipTxHash() public {
        TipTx memory tipTx = TipTx({
            gasLimit: 100_000,
            from: 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb,
            to: 0x6d2e03b7EfFEae98BD302A9F836D0d6Ab0002766,
            prePay: 1000,
            afterPay: 2000,
            nonce: 1,
            targetSlot: 1
        });
        vm.chainId(1337);
        bytes32 hash = tipTx.getTipTxHash();

        assertEq(hash, bytes32(0x6f8659a050af4ec085b502748f249504c344abfadae8a9308dc52d118c76511a));
    }
}
