// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

library ProposerRegistryLib {
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;
    uint256 public constant STAKE_AMOUNT = 0.01 ether; // just for testing now. TODO: figure out a better value
}

contract ProposerRegistry {
    enum ProposerStatus {
        OptedOut,
        OptIn,
        OptingOut
    }

    struct Proposer {
        bytes blsPubKey;
        address ethAddress;
        ProposerStatus status;
    }

    // Mapping to hold the proposers using BLS public key as the key
    mapping(bytes => Proposer) public proposers;
    // Mapping to link Ethereum addresses to BLS public keys
    mapping(address => bytes) public ethAddressToBLSPubKey;
    mapping(bytes => uint256) private optOutTimestamps;

    event ProposerOptedIn(bytes blsPubKey, address ethAddress);
    event ProposerOptedOut(bytes blsPubKey, address ethAddress);
    event ProposerStatusChanged(bytes blsPubKey, ProposerStatus status);

    constructor() { }

    function optIn(bytes calldata _blsPubKey) external payable {
        require(msg.value == ProposerRegistryLib.STAKE_AMOUNT, "stake amount not correct");
        require(proposers[_blsPubKey].ethAddress == address(0), "BLS public key already registered");
        require(ethAddressToBLSPubKey[msg.sender].length == 0, "Address already opted in");

        proposers[_blsPubKey] = Proposer(_blsPubKey, msg.sender, ProposerStatus.OptIn);
        ethAddressToBLSPubKey[msg.sender] = _blsPubKey;

        emit ProposerOptedIn(_blsPubKey, msg.sender);
        emit ProposerStatusChanged(_blsPubKey, ProposerStatus.OptIn);
    }

    function initOptOut() external {
        bytes memory blsPubKey = ethAddressToBLSPubKey[msg.sender];
        require(blsPubKey.length > 0, "Proposer does not exist");
        Proposer storage proposer = proposers[blsPubKey];
        require(proposer.status == ProposerStatus.OptIn, "Invalid status change");

        proposer.status = ProposerStatus.OptingOut;
        optOutTimestamps[blsPubKey] = block.timestamp;

        emit ProposerStatusChanged(blsPubKey, ProposerStatus.OptingOut);
    }

    function confirmOptOut() external {
        bytes memory blsPubKey = ethAddressToBLSPubKey[msg.sender];
        require(blsPubKey.length > 0, "Proposer does not exist");
        Proposer storage proposer = proposers[blsPubKey];
        require(proposer.status == ProposerStatus.OptingOut, "Not opting out");
        require(
            block.timestamp >= optOutTimestamps[blsPubKey] + ProposerRegistryLib.OPT_OUT_COOLDOWN,
            "Cooldown not elapsed"
        );

        proposer.status = ProposerStatus.OptedOut;
        proposer.ethAddress = address(0);
        delete ethAddressToBLSPubKey[msg.sender];

        (bool sent,) = msg.sender.call{ value: ProposerRegistryLib.STAKE_AMOUNT }("");
        require(sent, "Failed to send ETH");

        emit ProposerOptedOut(blsPubKey, msg.sender);
        emit ProposerStatusChanged(blsPubKey, ProposerStatus.OptedOut);
    }

    function getProposerStatus(bytes calldata blsPubKey) external view returns (ProposerStatus) {
        return proposers[blsPubKey].status;
    }
}
