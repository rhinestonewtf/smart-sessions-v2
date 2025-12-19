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

/// @title BaseConfigLib.initializeTokenOut Unit Tests
/// @notice Unit tests for the initializeTokenOut function
contract BaseConfigLib_initializeTokenOut_Unit_Test is BaseConfigLib_Unit_Test {
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

    /// @notice Test tokens
    address internal token1;
    address internal token2;

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
        token1 = address(0xb1);
        token2 = address(0xb2);
        chainId1 = 1;
        chainId2 = 137;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeTokenOutExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        bytes calldata _remaining = $.initializeTokenOut(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero entries
    function test_initializeTokenOut_withZeroEntries() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining = this.initializeTokenOutExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);
    }

    /// @notice Test with single entry
    function test_initializeTokenOut_withSingleEntry() external {
        // Arrange - count = 1, chainId1, token1
        data = abi.encodePacked(uint8(1), chainId1, token1);

        // Act
        remaining = this.initializeTokenOutExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.tokenOutSet[chainId1].length(), 1);
        assertTrue($.tokenOutSet[chainId1].contains(token1));
    }

    /// @notice Test with multiple entries same chain
    function test_initializeTokenOut_withMultipleEntriesSameChain() external {
        // Arrange - count = 2, both on chainId1
        data = abi.encodePacked(uint8(2), chainId1, token1, chainId1, token2);

        // Act
        remaining = this.initializeTokenOutExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.tokenOutSet[chainId1].length(), 2);
        assertTrue($.tokenOutSet[chainId1].contains(token1));
        assertTrue($.tokenOutSet[chainId1].contains(token2));
    }

    /// @notice Test with multiple entries different chains
    function test_initializeTokenOut_withMultipleEntriesDifferentChains() external {
        // Arrange - count = 2, different chains
        data = abi.encodePacked(uint8(2), chainId1, token1, chainId2, token2);

        // Act
        remaining = this.initializeTokenOutExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.tokenOutSet[chainId1].length(), 1);
        assertTrue($.tokenOutSet[chainId1].contains(token1));
        assertEq($.tokenOutSet[chainId2].length(), 1);
        assertTrue($.tokenOutSet[chainId2].contains(token2));
    }

    /// @notice Test with extra data after entries
    function test_initializeTokenOut_withExtraData() external {
        // Arrange
        bytes memory extraData = hex"cafebabe";
        data = abi.encodePacked(uint8(1), chainId1, token1, extraData);

        // Act
        remaining = this.initializeTokenOutExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Fuzz test for initializeTokenOut
    function testFuzz_initializeTokenOut(uint256 _chainId, address _token) external {
        // Arrange
        data = abi.encodePacked(uint8(1), _chainId, _token);

        // Act
        remaining = this.initializeTokenOutExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertTrue($.tokenOutSet[_chainId].contains(_token));
    }
}
