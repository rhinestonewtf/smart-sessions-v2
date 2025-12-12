// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Types
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseClaimPolicy.getModeConfig Unit Tests
/// @notice Unit tests for the getModeConfig function
contract BaseClaimPolicy_getModeConfig_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns stored modeConfig after initialization
    function test_getModeConfig_afterInitialization() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeArbiterConfig(_singleArbiter(arbiter1)));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        PolicyConfig result = policy.getModeConfig(configId, account);

        // Assert
        assertEq(PolicyConfig.unwrap(result), modeConfig);
    }

    /// @notice Test returns zero when not initialized
    function test_getModeConfig_notInitialized() external view {
        // Act
        PolicyConfig result = policy.getModeConfig(configId, account);

        // Assert
        assertEq(PolicyConfig.unwrap(result), 0);
    }

    /// @notice Test returns isolated modeConfig per configId
    function test_getModeConfig_isolatedPerConfigId() external {
        // Arrange
        uint32 modeConfig1 = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        uint32 modeConfig2 = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);

        ConfigId configId2 = ConfigId.wrap(bytes32(uint256(2)));

        bytes memory initData1 =
            abi.encodePacked(modeConfig1, _encodeArbiterConfig(_singleArbiter(arbiter1)));
        bytes memory initData2 = abi.encodePacked(modeConfig2, _encodeExpiryConfig(100, 1000));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData1);
        policy.initializeWithMultiplexer(account, configId2, initData2);

        // Assert
        assertEq(PolicyConfig.unwrap(policy.getModeConfig(configId, account)), modeConfig1);
        assertEq(PolicyConfig.unwrap(policy.getModeConfig(configId2, account)), modeConfig2);
    }

    /// @notice Test returns isolated modeConfig per account
    function test_getModeConfig_isolatedPerAccount() external {
        // Arrange
        uint32 modeConfig1 = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        uint32 modeConfig2 = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);

        address account2 = makeAddr("account2");

        bytes memory initData1 =
            abi.encodePacked(modeConfig1, _encodeArbiterConfig(_singleArbiter(arbiter1)));
        bytes memory initData2 = abi.encodePacked(modeConfig2, _encodeExpiryConfig(100, 1000));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData1);
        policy.initializeWithMultiplexer(account2, configId, initData2);

        // Assert
        assertEq(PolicyConfig.unwrap(policy.getModeConfig(configId, account)), modeConfig1);
        assertEq(PolicyConfig.unwrap(policy.getModeConfig(configId, account2)), modeConfig2);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _singleArbiter(address arbiter) internal pure returns (address[] memory) {
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter;
        return arbiters;
    }
}
