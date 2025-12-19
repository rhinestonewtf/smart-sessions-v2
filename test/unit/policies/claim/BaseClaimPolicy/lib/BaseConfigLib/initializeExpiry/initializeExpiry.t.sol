// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseConfigLib.initializeExpiry Unit Tests
/// @notice Unit tests for the initializeExpiry function
contract BaseConfigLib_initializeExpiry_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test config ID
    ConfigId internal configId;

    /// @notice Test account
    address internal account;

    /// @notice Remaining calldata
    bytes internal remaining;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = address(0x1234);
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeExpiryExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        bytes calldata _remaining = $.initializeExpiry(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero values
    function test_initializeExpiry_withZeroValues() external {
        // Arrange - packed = 0
        data = abi.encodePacked(uint256(0));

        // Act
        remaining = this.initializeExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        assertEq($.expiryConfig, 0);
    }

    /// @notice Test with only min value
    function test_initializeExpiry_revertsWhen_withOnlyMin() external {
        // Arrange - min = 1000, max = 0
        uint256 packed = uint256(1000);
        data = abi.encodePacked(packed);

        // Act / Assert
        vm.expectRevert(BaseConfigLib.InvalidBounds.selector);
        this.initializeExpiryExternal(configId, account, data);
    }

    /// @notice Test with only max value
    function test_initializeExpiry_withOnlyMax() external {
        // Arrange - min = 0, max = 2000
        uint256 packed = uint256(2000) << 128;
        data = abi.encodePacked(packed);

        // Act
        remaining = this.initializeExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128($.expiryConfig);
        assertEq(min, 0);
        assertEq(max, 2000);
    }

    /// @notice Test with both min and max
    function test_initializeExpiry_withBothValues() external {
        // Arrange - min = 1000, max = 2000
        uint256 packed = BaseConfigLib.packUint128(1000, 2000);
        data = abi.encodePacked(packed);

        // Act
        remaining = this.initializeExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128($.expiryConfig);
        assertEq(min, 1000);
        assertEq(max, 2000);
    }

    /// @notice Test with extra data after expiry
    function test_initializeExpiry_withExtraData() external {
        // Arrange
        uint256 packed = BaseConfigLib.packUint128(100, 200);
        bytes memory extraData = hex"deadbeef";
        data = abi.encodePacked(packed, extraData);

        // Act
        remaining = this.initializeExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Fuzz test for initializeExpiry
    function testFuzz_initializeExpiry(uint128 _min, uint128 _max) external {
        vm.assume(_min <= _max);
        // Arrange
        uint256 packed = BaseConfigLib.packUint128(_min, _max);
        data = abi.encodePacked(packed);

        // Act
        remaining = this.initializeExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128($.expiryConfig);
        assertEq(min, _min);
        assertEq(max, _max);
    }
}
