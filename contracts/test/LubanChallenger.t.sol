// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import "@axiom-crypto/axiom-std/AxiomTest.sol";
import { AverageBalance } from "@axiom-crypto/axiom-std/../test/example/AverageBalance.sol";

contract LubanChallengerTest is AxiomTest {
    using Axiom for Query;

    struct AxiomInput {
        uint64 blockNumber;
        address _address;
    }

    // LubanChallenger public LubanChallenger; // unused
    AxiomInput public input;
    AverageBalance averageBalance;
    bytes32 public querySchema;

    function setUp() public {
        // _createSelectForkAndSetupAxiom("sepolia", 5_103_100);

        // input =
        //     AxiomInput({ blockNumber: 4_205_938, _address: address(0x8018fe32fCFd3d166E8b4c4E37105318A84BA11b) });
        // querySchema = axiomVm.readCircuit("test/circuit/average.circuit.ts");
        // averageBalance = new AverageBalance(axiomV2QueryAddress, uint64(block.chainid), querySchema);
    }

    function test_simple_example() public {
        // create a query into Axiom with default parameters
        // Query memory q = query(querySchema, abi.encode(input), address(averageBalance));

        // // send the query to Axiom
        // q.send();

        // // prank fulfillment of the query, returning the Axiom results
        // bytes32[] memory results = q.prankFulfill();

        // // parse Axiom results and verify length is as expected
        // assertEq(results.length, 3);
        // uint256 blockNumber = uint256(results[0]);
        // address addr = address(uint160(uint256(results[1])));
        // uint256 avg = uint256(results[2]);

        // // verify the average balance recorded in AverageBalance is as expected
        // assertEq(avg, averageBalance.provenAverageBalances(blockNumber, addr));
    }
}
