// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title MockSubPolicy
/// @notice Mock sub-policy for testing initializeSubPolicies
contract MockSubPolicy {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Count of initializeWithMultiplexer calls
    uint256 public initializeWithMultiplexerCallCount;

    /// @notice Last configId passed to initializeWithMultiplexer
    ConfigId public lastConfigId;

    /// @notice Last account passed to initializeWithMultiplexer
    address public lastAccount;

    /// @notice Last init data passed to initializeWithMultiplexer
    bytes public lastInitData;

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mock initializeWithMultiplexer implementation
    function initializeWithMultiplexer(
        address _account,
        ConfigId _configId,
        bytes calldata _initData
    )
        external
    {
        initializeWithMultiplexerCallCount++;
        lastConfigId = _configId;
        lastAccount = _account;
        lastInitData = _initData;
    }
}
