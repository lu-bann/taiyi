// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./EigenLayerMiddleware.sol";

contract ValidatorAVS is EigenLayerMiddleware {
/// @notice Just reuse the base createOperatorDirectedAVSRewardsSubmission
/// for normal distribution. For "passive validators", no special splitting needed.

// Optionally override or implement more specialized logic here if needed.
// But for now, we just inherit the default behavior.
}
