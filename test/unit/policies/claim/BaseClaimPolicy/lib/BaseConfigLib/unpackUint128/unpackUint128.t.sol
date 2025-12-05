// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.unpackUint128 Unit Tests
/// @notice Unit tests for the unpackUint128 function
contract BaseConfigLib_unpackUint128_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result lower value
    uint128 internal lower;

    /// @notice Result upper value
    uint128 internal upper;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test unpacking zero value
    function test_unpackUint128_withZeroValue() external {
        // Act
        (lower, upper) = BaseConfigLib.unpackUint128(0);

        // Assert
        assertEq(lower, 0);
        assertEq(upper, 0);
    }

    /// @notice Test unpacking only lower bits set
    function test_unpackUint128_withOnlyLower() external {
        // Arrange
        uint256 packed = 12_345;

        // Act
        (lower, upper) = BaseConfigLib.unpackUint128(packed);

        // Assert
        assertEq(lower, 12_345);
        assertEq(upper, 0);
    }

    /// @notice Test unpacking only upper bits set
    function test_unpackUint128_withOnlyUpper() external {
        // Arrange
        uint256 packed = uint256(67_890) << 128;

        // Act
        (lower, upper) = BaseConfigLib.unpackUint128(packed);

        // Assert
        assertEq(lower, 0);
        assertEq(upper, 67_890);
    }

    /// @notice Test unpacking both values
    function test_unpackUint128_withBothValues() external {
        // Arrange
        uint256 packed = uint256(111) | (uint256(222) << 128);

        // Act
        (lower, upper) = BaseConfigLib.unpackUint128(packed);

        // Assert
        assertEq(lower, 111);
        assertEq(upper, 222);
    }

    /// @notice Test unpacking max value
    function test_unpackUint128_withMaxValue() external {
        // Arrange
        uint256 packed = type(uint256).max;

        // Act
        (lower, upper) = BaseConfigLib.unpackUint128(packed);

        // Assert
        assertEq(lower, type(uint128).max);
        assertEq(upper, type(uint128).max);
    }

    /// @notice Fuzz test for unpackUint128
    /// @param _packed Random packed value
    function testFuzz_unpackUint128(uint256 _packed) external {
        // Act
        (lower, upper) = BaseConfigLib.unpackUint128(_packed);

        // Assert
        assertEq(lower, uint128(_packed));
        assertEq(upper, uint128(_packed >> 128));
    }
}
