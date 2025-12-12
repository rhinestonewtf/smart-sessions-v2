// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseConfigLib.initializeArbiter Unit Tests
/// @notice Unit tests for the initializeArbiter function
contract BaseConfigLib_initializeArbiter_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test config ID
    ConfigId internal configId;

    /// @notice Test account
    address internal account;

    /// @notice Remaining calldata
    bytes internal remaining;

    /// @notice Test arbiters
    address internal arbiter1;
    address internal arbiter2;
    address internal arbiter3;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = address(0x1234);
        arbiter1 = address(0xA1);
        arbiter2 = address(0xA2);
        arbiter3 = address(0xA3);
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeArbiterExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account);
        bytes calldata _remaining = $.initializeArbiter(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero arbiters
    function test_initializeArbiter_withZeroArbiters() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining = this.initializeArbiterExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage is empty
        BasePolicyStorage storage $ = configId.getStorage(account);
        assertEq($.arbiterConfig.length(), 0);
    }

    /// @notice Test with single arbiter
    function test_initializeArbiter_withSingleArbiter() external {
        // Arrange - count = 1, arbiter1
        data = abi.encodePacked(uint8(1), arbiter1);

        // Act
        remaining = this.initializeArbiterExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ = configId.getStorage(account);
        assertEq($.arbiterConfig.length(), 1);
        assertTrue($.arbiterConfig.contains(arbiter1));
    }

    /// @notice Test with multiple arbiters
    function test_initializeArbiter_withMultipleArbiters() external {
        // Arrange - count = 3, arbiter1, arbiter2, arbiter3
        data = abi.encodePacked(uint8(3), arbiter1, arbiter2, arbiter3);

        // Act
        remaining = this.initializeArbiterExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ = configId.getStorage(account);
        assertEq($.arbiterConfig.length(), 3);
        assertTrue($.arbiterConfig.contains(arbiter1));
        assertTrue($.arbiterConfig.contains(arbiter2));
        assertTrue($.arbiterConfig.contains(arbiter3));
    }

    /// @notice Test with extra data after arbiters
    function test_initializeArbiter_withExtraData() external {
        // Arrange - count = 1, arbiter1, extra data
        bytes memory extraData = hex"cafebabe";
        data = abi.encodePacked(uint8(1), arbiter1, extraData);

        // Act
        remaining = this.initializeArbiterExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));

        // Verify storage
        BasePolicyStorage storage $ = configId.getStorage(account);
        assertEq($.arbiterConfig.length(), 1);
        assertTrue($.arbiterConfig.contains(arbiter1));
    }

    /// @notice Fuzz test for initializeArbiter
    function testFuzz_initializeArbiter(address[5] memory _arbiters, uint8 _count) external {
        // Bound count to array size
        _count = uint8(bound(_count, 0, 5));

        // Arrange - build data
        data = abi.encodePacked(_count);
        for (uint8 i = 0; i < _count; i++) {
            data = abi.encodePacked(data, _arbiters[i]);
        }

        // Act
        remaining = this.initializeArbiterExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage - note: duplicates won't be added twice
        BasePolicyStorage storage $ = configId.getStorage(account);
        for (uint8 i = 0; i < _count; i++) {
            assertTrue($.arbiterConfig.contains(_arbiters[i]));
        }
    }
}
