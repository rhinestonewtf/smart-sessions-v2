// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseConfigLib.initializeFillExpiry Unit Tests
/// @notice Unit tests for the initializeFillExpiry function
contract BaseConfigLib_initializeFillExpiry_Unit_Test is BaseConfigLib_Unit_Test {
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

    /// @notice Test chain IDs
    uint256 internal chainId1;
    uint256 internal chainId2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = address(0x1234);
        chainId1 = 1;
        chainId2 = 137;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeFillExpiryExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        bytes calldata _remaining = $.initializeFillExpiry(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero entries
    function test_initializeFillExpiry_withZeroEntries() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining = this.initializeFillExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);
    }

    /// @notice Test with single entry
    function test_initializeFillExpiry_withSingleEntry() external {
        // Arrange - count = 1, chainId, packed(min, max)
        uint256 packed = BaseConfigLib.packUint128(100, 200);
        data = abi.encodePacked(uint8(1), chainId1, packed);

        // Act
        remaining = this.initializeFillExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128($.fillExpiryConfig[chainId1]);
        assertEq(min, 100);
        assertEq(max, 200);
    }

    /// @notice Test with multiple entries
    function test_initializeFillExpiry_withMultipleEntries() external {
        // Arrange - count = 2
        uint256 packed1 = BaseConfigLib.packUint128(100, 200);
        uint256 packed2 = BaseConfigLib.packUint128(300, 400);
        data = abi.encodePacked(uint8(2), chainId1, packed1, chainId2, packed2);

        // Act
        remaining = this.initializeFillExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        (uint128 min1, uint128 max1) = BaseConfigLib.unpackUint128($.fillExpiryConfig[chainId1]);
        assertEq(min1, 100);
        assertEq(max1, 200);

        (uint128 min2, uint128 max2) = BaseConfigLib.unpackUint128($.fillExpiryConfig[chainId2]);
        assertEq(min2, 300);
        assertEq(max2, 400);
    }

    /// @notice Test with extra data after entries
    function test_initializeFillExpiry_withExtraData() external {
        // Arrange
        uint256 packed = BaseConfigLib.packUint128(100, 200);
        bytes memory extraData = hex"deadbeef";
        data = abi.encodePacked(uint8(1), chainId1, packed, extraData);

        // Act
        remaining = this.initializeFillExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Fuzz test for initializeFillExpiry
    function testFuzz_initializeFillExpiry(uint256 _chainId, uint128 _min, uint128 _max) external {
        vm.assume(_min <= _max);
        // Arrange
        uint256 packed = BaseConfigLib.packUint128(_min, _max);
        data = abi.encodePacked(uint8(1), _chainId, packed);

        // Act
        remaining = this.initializeFillExpiryExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128($.fillExpiryConfig[_chainId]);
        assertEq(min, _min);
        assertEq(max, _max);
    }
}
