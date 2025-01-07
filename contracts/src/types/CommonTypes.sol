// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

enum PreconfRequestStatus {
    NonInitiated, // default value
    Exhausted,
    Executed,
    Collected
}
