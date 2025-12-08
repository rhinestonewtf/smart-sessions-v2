// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseStorageLib_Unit_Test } from "../BaseStorageLib.t.sol";

// Libraries
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseStorageLib.getStorage Unit Tests
/// @notice Unit tests for the getStorage function
contract BaseStorageLib_getStorage_Unit_Test is BaseStorageLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to get storage slot
    function getStorageSlotExternal(
        ConfigId id,
        address account
    )
        external
        pure
        returns (bytes32 slot)
    {
        BasePolicyStorage storage $ = BaseStorageLib.getStorage(id, account);
        assembly {
            slot := $.slot
        }
    }

    /// @notice External wrapper to write modeConfig to storage
    function writeModeConfigExternal(ConfigId id, address account, uint32 value) external {
        BasePolicyStorage storage $ = BaseStorageLib.getStorage(id, account);
        $.modeConfig = PolicyConfig.wrap(value);
    }

    /// @notice External wrapper to read modeConfig from storage
    function readModeConfigExternal(ConfigId id, address account) external view returns (uint32) {
        BasePolicyStorage storage $ = BaseStorageLib.getStorage(id, account);
        return PolicyConfig.unwrap($.modeConfig);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that getStorage returns a valid storage pointer
    function test_getStorage_returnsValidStoragePointer() external view {
        // Act
        bytes32 slot = this.getStorageSlotExternal(configId1, account1);

        // Assert - slot should be non-zero
        assertTrue(slot != bytes32(0));
    }

    /// @notice Test that getStorage allows writing and reading from storage
    function test_getStorage_allowsWritingAndReading() external {
        // Arrange
        uint32 testValue = 0x12345678;

        // Act
        this.writeModeConfigExternal(configId1, account1, testValue);
        uint32 readValue = this.readModeConfigExternal(configId1, account1);

        // Assert
        assertEq(readValue, testValue);
    }

    /// @notice Test that different accounts get isolated storage
    function test_getStorage_isolatesStoragePerAccount() external {
        // Arrange
        uint32 value1 = 0xAAAAAAAA;
        uint32 value2 = 0xBBBBBBBB;

        // Act - write different values for different accounts
        this.writeModeConfigExternal(configId1, account1, value1);
        this.writeModeConfigExternal(configId1, account2, value2);

        // Assert - each account should have its own value
        assertEq(this.readModeConfigExternal(configId1, account1), value1);
        assertEq(this.readModeConfigExternal(configId1, account2), value2);
    }

    /// @notice Test that different configIds get isolated storage
    function test_getStorage_isolatesStoragePerConfigId() external {
        // Arrange
        uint32 value1 = 0xCCCCCCCC;
        uint32 value2 = 0xDDDDDDDD;

        // Act - write different values for different configIds
        this.writeModeConfigExternal(configId1, account1, value1);
        this.writeModeConfigExternal(configId2, account1, value2);

        // Assert - each configId should have its own value
        assertEq(this.readModeConfigExternal(configId1, account1), value1);
        assertEq(this.readModeConfigExternal(configId2, account1), value2);
    }

    /// @notice Test that same configId/account returns same slot
    function test_getStorage_returnsSameSlotForSamePair() external view {
        // Act
        bytes32 slot1 = this.getStorageSlotExternal(configId1, account1);
        bytes32 slot2 = this.getStorageSlotExternal(configId1, account1);

        // Assert
        assertEq(slot1, slot2);
    }

    /// @notice Test that different accounts return different slots
    function test_getStorage_returnsDifferentSlotsForDifferentAccounts() external view {
        // Act
        bytes32 slot1 = this.getStorageSlotExternal(configId1, account1);
        bytes32 slot2 = this.getStorageSlotExternal(configId1, account2);

        // Assert
        assertTrue(slot1 != slot2);
    }

    /// @notice Test that different configIds return different slots
    function test_getStorage_returnsDifferentSlotsForDifferentConfigIds() external view {
        // Act
        bytes32 slot1 = this.getStorageSlotExternal(configId1, account1);
        bytes32 slot2 = this.getStorageSlotExternal(configId2, account1);

        // Assert
        assertTrue(slot1 != slot2);
    }

    /// @notice Fuzz test for storage isolation
    function testFuzz_getStorage_isolatesStorage(
        bytes32 _configId1,
        bytes32 _configId2,
        address _account1,
        address _account2,
        uint32 _value1,
        uint32 _value2
    )
        external
    {
        // Skip if pairs are identical
        vm.assume(_configId1 != _configId2 || _account1 != _account2);

        // Arrange
        ConfigId id1 = ConfigId.wrap(_configId1);
        ConfigId id2 = ConfigId.wrap(_configId2);

        // Act - write to both locations
        this.writeModeConfigExternal(id1, _account1, _value1);
        this.writeModeConfigExternal(id2, _account2, _value2);

        // Assert - values should be independent
        assertEq(this.readModeConfigExternal(id1, _account1), _value1);
        assertEq(this.readModeConfigExternal(id2, _account2), _value2);
    }
}
