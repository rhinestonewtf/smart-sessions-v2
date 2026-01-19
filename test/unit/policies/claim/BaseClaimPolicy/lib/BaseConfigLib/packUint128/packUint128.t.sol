// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.packUint128 Unit Tests
/// @notice Unit tests for the packUint128 function
contract BaseConfigLib_packUint128_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result packed value
    uint256 internal packed;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test packing zero values
    function test_packUint128_withZeroValues() external {
        // Act
        packed = BaseConfigLib.packUint128(0, 0);

        // Assert
        assertEq(packed, 0);
    }

    /// @notice Test packing only lower value
    function test_packUint128_withOnlyLower() external {
        // Arrange
        uint128 lower = 12_345;

        // Act
        packed = BaseConfigLib.packUint128(lower, 0);

        // Assert
        assertEq(packed, 12_345);
    }

    /// @notice Test packing only upper value
    function test_packUint128_withOnlyUpper() external {
        // Arrange
        uint128 upper = 67_890;

        // Act
        packed = BaseConfigLib.packUint128(0, upper);

        // Assert
        assertEq(packed, uint256(upper) << 128);
    }

    /// @notice Test packing both values
    function test_packUint128_withBothValues() external {
        // Arrange
        uint128 lower = 111;
        uint128 upper = 222;

        // Act
        packed = BaseConfigLib.packUint128(lower, upper);

        // Assert
        assertEq(uint128(packed), lower);
        assertEq(uint128(packed >> 128), upper);
    }

    /// @notice Test packing max values
    function test_packUint128_withMaxValues() external {
        // Arrange
        uint128 lower = type(uint128).max;
        uint128 upper = type(uint128).max;

        // Act
        packed = BaseConfigLib.packUint128(lower, upper);

        // Assert
        assertEq(packed, type(uint256).max);
    }

    /// @notice Fuzz test for packUint128
    /// @param _lower Random lower value
    /// @param _upper Random upper value
    function testFuzz_packUint128(uint128 _lower, uint128 _upper) external {
        // Act
        packed = BaseConfigLib.packUint128(_lower, _upper);

        // Assert
        assertEq(uint128(packed), _lower);
        assertEq(uint128(packed >> 128), _upper);
    }
}
