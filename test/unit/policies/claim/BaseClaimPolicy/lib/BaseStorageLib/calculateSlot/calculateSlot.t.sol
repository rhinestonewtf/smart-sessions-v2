// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseStorageLib_Unit_Test } from "../BaseStorageLib.t.sol";

// Libraries
import { BaseStorageLib } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseStorageLib.calculateSlot Unit Tests
/// @notice Unit tests for the calculateSlot function
contract BaseStorageLib_calculateSlot_Unit_Test is BaseStorageLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test base slot
    bytes32 internal baseSlot;

    /// @notice Result slot
    bytes32 internal resultSlot;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to calculate slot
    function calculateSlotExternal(
        bytes32 _baseSlot,
        ConfigId id,
        address account
    )
        external
        pure
        returns (bytes32)
    {
        return BaseStorageLib.calculateSlot(_baseSlot, id, account);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that calculateSlot returns a deterministic slot
    function test_calculateSlot_returnsDeterministicSlot() external {
        // Arrange
        baseSlot = EXPECTED_STORAGE_POSITION;

        // Act
        bytes32 slot1 = this.calculateSlotExternal(baseSlot, configId1, account1);
        bytes32 slot2 = this.calculateSlotExternal(baseSlot, configId1, account1);

        // Assert
        assertEq(slot1, slot2);
    }

    /// @notice Test that calculateSlot matches manual keccak256 computation
    function test_calculateSlot_matchesKeccak256() external {
        // Arrange
        baseSlot = EXPECTED_STORAGE_POSITION;

        // Act
        resultSlot = this.calculateSlotExternal(baseSlot, configId1, account1);

        // Assert - compute expected value manually
        bytes32 expected = keccak256(abi.encode(baseSlot, ConfigId.unwrap(configId1), account1));
        assertEq(resultSlot, expected);
    }

    /// @notice Test that different baseSlots return different slots
    function test_calculateSlot_differentBaseSlotsReturnDifferentSlots() external view {
        // Arrange
        bytes32 baseSlot1 = bytes32(uint256(1));
        bytes32 baseSlot2 = bytes32(uint256(2));

        // Act
        bytes32 slot1 = this.calculateSlotExternal(baseSlot1, configId1, account1);
        bytes32 slot2 = this.calculateSlotExternal(baseSlot2, configId1, account1);

        // Assert
        assertTrue(slot1 != slot2);
    }

    /// @notice Test that different configIds return different slots
    function test_calculateSlot_differentConfigIdsReturnDifferentSlots() external {
        // Arrange
        baseSlot = EXPECTED_STORAGE_POSITION;

        // Act
        bytes32 slot1 = this.calculateSlotExternal(baseSlot, configId1, account1);
        bytes32 slot2 = this.calculateSlotExternal(baseSlot, configId2, account1);

        // Assert
        assertTrue(slot1 != slot2);
    }

    /// @notice Test that different accounts return different slots
    function test_calculateSlot_differentAccountsReturnDifferentSlots() external {
        // Arrange
        baseSlot = EXPECTED_STORAGE_POSITION;

        // Act
        bytes32 slot1 = this.calculateSlotExternal(baseSlot, configId1, account1);
        bytes32 slot2 = this.calculateSlotExternal(baseSlot, configId1, account2);

        // Assert
        assertTrue(slot1 != slot2);
    }

    /// @notice Test that STORAGE_POSITION constant is correct
    function test_calculateSlot_storagePositionConstantIsCorrect() external pure {
        // Act
        bytes32 storedPosition = BaseStorageLib.STORAGE_POSITION;

        // Assert
        assertEq(storedPosition, EXPECTED_STORAGE_POSITION);

        // Verify it equals keccak256("rhinestone.storage.BaseClaimPolicy") - 1
        bytes32 computed = bytes32(uint256(keccak256("rhinestone.storage.BaseClaimPolicy")) - 1);
        assertEq(storedPosition, computed);
    }

    /// @notice Test that zero values still return valid slot
    function test_calculateSlot_withZeroValues() external {
        // Arrange
        bytes32 zeroBaseSlot = bytes32(0);
        ConfigId zeroConfigId = ConfigId.wrap(bytes32(0));
        address zeroAccount = address(0);

        // Act
        resultSlot = this.calculateSlotExternal(zeroBaseSlot, zeroConfigId, zeroAccount);

        // Assert - should still return a valid (non-zero due to keccak) slot
        bytes32 expected = keccak256(abi.encode(zeroBaseSlot, bytes32(0), zeroAccount));
        assertEq(resultSlot, expected);
    }

    /// @notice Fuzz test for calculateSlot determinism
    function testFuzz_calculateSlot_isDeterministic(
        bytes32 _baseSlot,
        bytes32 _configId,
        address _account
    )
        external
        view
    {
        // Arrange
        ConfigId id = ConfigId.wrap(_configId);

        // Act
        bytes32 slot1 = this.calculateSlotExternal(_baseSlot, id, _account);
        bytes32 slot2 = this.calculateSlotExternal(_baseSlot, id, _account);

        // Assert
        assertEq(slot1, slot2);
    }

    /// @notice Fuzz test that calculateSlot matches keccak256
    function testFuzz_calculateSlot_matchesKeccak256(
        bytes32 _baseSlot,
        bytes32 _configId,
        address _account
    )
        external
    {
        // Arrange
        ConfigId id = ConfigId.wrap(_configId);

        // Act
        resultSlot = this.calculateSlotExternal(_baseSlot, id, _account);

        // Assert
        bytes32 expected = keccak256(abi.encode(_baseSlot, _configId, _account));
        assertEq(resultSlot, expected);
    }

    /// @notice Fuzz test verifies no storage collisions across configId/account pairs
    function testFuzz_calculateSlot_noCollisions(
        bytes32 configId1Raw,
        bytes32 configId2Raw,
        address account1,
        address account2
    )
        external
        view
    {
        // Skip if both pairs are identical
        vm.assume(configId1Raw != configId2Raw || account1 != account2);

        ConfigId configId1 = ConfigId.wrap(configId1Raw);
        ConfigId configId2 = ConfigId.wrap(configId2Raw);

        // Act
        bytes32 slot1 = this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, configId1, account1);
        bytes32 slot2 = this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, configId2, account2);

        // Assert - different inputs should produce different slots
        assertNotEq(slot1, slot2);
    }

    /// @notice Test storage isolation with realistic configId/account combinations
    function test_calculateSlot_isolationMatrix() external view {
        // Arrange
        ConfigId configIdA = ConfigId.wrap(bytes32(uint256(1)));
        ConfigId configIdB = ConfigId.wrap(bytes32(uint256(2)));
        address accountA = address(0x1111111111111111111111111111111111111111);
        address accountB = address(0x2222222222222222222222222222222222222222);

        // Act - calculate all 4 combinations
        bytes32 slotAA = this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, configIdA, accountA);
        bytes32 slotAB = this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, configIdA, accountB);
        bytes32 slotBA = this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, configIdB, accountA);
        bytes32 slotBB = this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, configIdB, accountB);

        // Assert - all slots are unique
        assertNotEq(slotAA, slotAB);
        assertNotEq(slotAA, slotBA);
        assertNotEq(slotAA, slotBB);
        assertNotEq(slotAB, slotBA);
        assertNotEq(slotAB, slotBB);
        assertNotEq(slotBA, slotBB);
    }

    /// @notice Test with configId = bytes32(0)
    function test_calculateSlot_zeroConfigId() external view {
        // Arrange
        ConfigId zeroConfigId = ConfigId.wrap(bytes32(0));
        address testAccount = address(0x1234);

        // Act
        bytes32 slot =
            this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, zeroConfigId, testAccount);

        // Assert - should produce valid non-zero slot
        assertNotEq(slot, bytes32(0));
    }

    /// @notice Test with account = address(0)
    function test_calculateSlot_zeroAccount() external view {
        // Arrange
        ConfigId testConfigId = ConfigId.wrap(bytes32(uint256(1)));
        address zeroAccount = address(0);

        // Act
        bytes32 slot =
            this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, testConfigId, zeroAccount);

        // Assert - should produce valid non-zero slot
        assertNotEq(slot, bytes32(0));
    }

    /// @notice Test with both configId and account = 0
    function test_calculateSlot_allZeros() external view {
        // Arrange
        ConfigId zeroConfigId = ConfigId.wrap(bytes32(0));
        address zeroAccount = address(0);

        // Act
        bytes32 slot =
            this.calculateSlotExternal(EXPECTED_STORAGE_POSITION, zeroConfigId, zeroAccount);

        // Assert - should still produce valid non-zero slot (due to STORAGE_POSITION)
        assertNotEq(slot, bytes32(0));
    }
}
