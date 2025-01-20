// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./EigenLayerMiddleware.sol";
import "./ValidatorAVS.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GatewayAVS is EigenLayerMiddleware {

    /// @notice The remainder goes to the validator AVS
    ValidatorAVS public validatorAVS;

    event GatewayShareUpdated(uint256 oldBips, uint256 newBips);

    /// @notice Initialize function (same signature as abstract, if we prefer)
    function initialize(
        address _owner,
        address _proposerRegistry,
        address _avsDirectory,
        address _delegationManager,
        address _strategyManager,
        address _eigenPodManager,
        address _rewardCoordinator,
        address _rewardInitiator,
        address _validatorAVS,
        uint256 _gatewayShareBips
    )
        public
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();

        proposerRegistry = TaiyiProposerRegistry(_proposerRegistry);
        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_delegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_strategyManager);
        EIGEN_POD_MANAGER = IEigenPodManager(_eigenPodManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_rewardCoordinator);

        _setRewardsInitiator(_rewardInitiator);

        validatorAVS = ValidatorAVS(_validatorAVS);
        GATEWAY_SHARE_BIPS = _gatewayShareBips;
    }

    function _createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
            operatorDirectedRewardsSubmissions
    )
        internal
        override
    {
        for (uint256 i = 0; i < operatorDirectedRewardsSubmissions.length; ++i) {
            // Calculate total amount of token to transfer
            IERC20 token = IERC20(address(operatorDirectedRewardsSubmissions[i].token));
            uint256 totalAmount = 0;

            for (
                uint256 j = 0;
                j < operatorDirectedRewardsSubmissions[i].operatorRewards.length;
                ++j
            ) {
                totalAmount +=
                    operatorDirectedRewardsSubmissions[i].operatorRewards[j].amount;
            }

            token.transferFrom(msg.sender, address(this), totalAmount);

            // GATEWAY_SHARE_BIPS represents the gateway's share in basis points (1 bip = 0.01%)
            // For example, if GATEWAY_SHARE_BIPS = 1000, gateway gets 10% of total rewards
            // First calculate gateway's portion by multiplying total by bips/10000
            uint256 gatewayAmount = (totalAmount * GATEWAY_SHARE_BIPS) / 10_000;
            uint256 validatorAmount = totalAmount - gatewayAmount;

            // Handle validator portion if amount is non-zero
            if (validatorAmount > 0) {
                // Approve validator portion to ValidatorAVS contract
                token.approve(address(validatorAVS), validatorAmount);

                // Create validator rewards submission
                IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory
                    validatorSubmission = _createSingleOperatorSubmission(
                        operatorDirectedRewardsSubmissions[i].operatorRewards[0].operator,
                        validatorAmount,
                        operatorDirectedRewardsSubmissions[i],
                        "Taiyi Validator AVS"
                    );

                // Submit validator rewards
                REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(
                    address(this), validatorSubmission
                );
            }

            // Approve gateway portion to RewardsCoordinator
            token.approve(address(REWARDS_COORDINATOR), gatewayAmount);

            // Create gateway portion rewards submission
            IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory
                gatewaySubmissions = _createSingleOperatorSubmission(
                    operatorDirectedRewardsSubmissions[i].operatorRewards[0].operator,
                    gatewayAmount,
                    operatorDirectedRewardsSubmissions[i],
                    "Taiyi Gateway AVS"
                );

            REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(
                address(this), gatewaySubmissions
            );
        }
    }

    /// @notice Helper function to create operator directed rewards submission for a single operator
    /// @param operator The operator address to receive rewards
    /// @param amount The amount of rewards for the operator
    /// @param submission The original submission to copy other parameters from
    /// @param suffix Optional suffix to append to description
    /// @return submissions Array containing single operator directed rewards submission
    function _createSingleOperatorSubmission(
        address operator,
        uint256 amount,
        IRewardsCoordinator.OperatorDirectedRewardsSubmission memory submission,
        string memory suffix
    )
        internal
        pure
        returns (IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory)
    {
        // Create operator reward array with single entry
        IRewardsCoordinator.OperatorReward[] memory operatorReward =
            new IRewardsCoordinator.OperatorReward[](1);
        operatorReward[0] =
            IRewardsCoordinator.OperatorReward({ operator: operator, amount: amount });

        // Create submissions array with single entry
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);
        submissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: operatorReward,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(abi.encodePacked(submission.description, suffix))
        });

        return submissions;
    }

    function setGatewayShareBips(uint256 newShareBips) external onlyOwner {
        require(newShareBips <= 10_000, "Invalid share bips");
        emit GatewayShareUpdated(GATEWAY_SHARE_BIPS, newShareBips);
        GATEWAY_SHARE_BIPS = newShareBips;
    }
}
