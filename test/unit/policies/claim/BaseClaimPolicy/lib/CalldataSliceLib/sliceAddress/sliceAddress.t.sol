// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceAddress Unit Tests
/// @notice Unit tests for the sliceAddress function
contract CalldataSliceLib_sliceAddress_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    address internal val;

    /// @notice Expected value for assertions
    address internal expected;

    /// @notice Additional values for sequential read tests
    address internal val1;
    address internal val2;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced address and new offset
    function sliceAddressExternal(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (address, uint256)
    {
        return _data.sliceAddress(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing address at start of data
    function test_sliceAddress_withValidAddressAtStart() external {
        // Arrange
        expected = address(0x1234567890AbcdEF1234567890aBcdef12345678);
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceAddressExternal(data, 0);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 20);
    }

    /// @notice Test slicing address at non-zero offset
    function test_sliceAddress_withAddressAtOffset() external {
        // Arrange
        expected = address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF);
        data = abi.encodePacked(bytes32(0), expected);

        // Act
        (val, newOffset) = this.sliceAddressExternal(data, 32);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 52);
    }

    /// @notice Test that trailing data is not included in result
    function test_sliceAddress_withTrailingData() external {
        // Arrange
        expected = address(0x1111111111111111111111111111111111111111);
        bytes12 trailing = bytes12(uint96(0xFFFFFFFFFFFFFFFFFFFFFFFF));
        data = abi.encodePacked(expected, trailing);

        // Act
        (val, newOffset) = this.sliceAddressExternal(data, 0);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 20);
    }

    /// @notice Test sequential reads with advancing offset
    function test_sliceAddress_withSequentialReads() external {
        // Arrange
        address first = address(0x1111111111111111111111111111111111111111);
        address second = address(0x2222222222222222222222222222222222222222);
        data = abi.encodePacked(first, second);

        // Act
        (val1, offset) = this.sliceAddressExternal(data, 0);
        (val2, offset) = this.sliceAddressExternal(data, offset);

        // Assert
        assertEq(val1, first);
        assertEq(val2, second);
        assertEq(offset, 40);
    }

    /// @notice Fuzz test for sliceAddress with random values and offsets
    /// @param _expected Random address value to encode and read
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceAddress(address _expected, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _expected);

        // Act
        (val, newOffset) = this.sliceAddressExternal(data, _prefixLen);

        // Assert
        assertEq(val, _expected);
        assertEq(newOffset, uint256(_prefixLen) + 20);
    }
}
