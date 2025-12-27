// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IActionPolicy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Mock Spending Limit Policy
/// @notice Simple action policy for testing - validates value limits and call counts
contract MockSpendingLimitPolicy is IActionPolicy {
    struct PolicyConfig {
        uint256 maxValue;
        uint256 totalSpent;
        uint256 maxCallsPerSession;
        uint256 callCount;
        bool initialized;
    }

    /// @notice Config storage: multiplexer => account => config
    mapping(address => mapping(address => PolicyConfig)) public configs;

    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        (,, uint256 maxValue, uint256 maxCallsPerSession) =
            abi.decode(initData, (address, bytes4, uint256, uint256));

        configs[msg.sender][account] = PolicyConfig({
            maxValue: maxValue,
            totalSpent: 0,
            maxCallsPerSession: maxCallsPerSession,
            callCount: 0,
            initialized: true
        });

        emit PolicySet(configId, msg.sender, account);
    }

    function checkAction(
        ConfigId,
        address account,
        address,
        uint256 value,
        bytes calldata
    )
        external
        override
        returns (uint256)
    {
        PolicyConfig storage config = configs[msg.sender][account];

        if (!config.initialized) {
            return 1;
        }

        if (value > config.maxValue) {
            return 1;
        }

        if (config.totalSpent + value > config.maxValue * 10) {
            return 1;
        }

        if (config.maxCallsPerSession > 0 && config.callCount >= config.maxCallsPerSession) {
            return 1;
        }

        config.totalSpent += value;
        config.callCount += 1;

        return 0;
    }

    function getPolicyState(
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256 totalSpent, uint256 callCount, bool initialized)
    {
        PolicyConfig storage config = configs[multiplexer][account];
        return (config.totalSpent, config.callCount, config.initialized);
    }

    function resetCounters(address multiplexer, address account) external {
        configs[multiplexer][account].totalSpent = 0;
        configs[multiplexer][account].callCount = 0;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IPolicy).interfaceId
            || interfaceId == type(IActionPolicy).interfaceId;
    }
}
