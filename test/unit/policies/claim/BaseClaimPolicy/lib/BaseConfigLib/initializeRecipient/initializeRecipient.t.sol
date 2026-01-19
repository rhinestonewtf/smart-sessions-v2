// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseConfigLib.initializeRecipient Unit Tests
/// @notice Unit tests for the initializeRecipient function
contract BaseConfigLib_initializeRecipient_Unit_Test is BaseConfigLib_Unit_Test {
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

    /// @notice Test recipients
    address internal recipient1;
    address internal recipient2;

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
        recipient1 = address(0xa1);
        recipient2 = address(0xa2);
        chainId1 = 1;
        chainId2 = 137;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeRecipientExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        bytes calldata _remaining = $.initializeRecipient(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero entries
    function test_initializeRecipient_withZeroEntries() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining = this.initializeRecipientExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);
    }

    /// @notice Test with single entry
    function test_initializeRecipient_withSingleEntry() external {
        // Arrange - count = 1, chainId1, recipient1
        data = abi.encodePacked(uint8(1), chainId1, recipient1);

        // Act
        remaining = this.initializeRecipientExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        assertEq($.recipientConfig[chainId1], recipient1);
    }

    /// @notice Test with multiple entries
    function test_initializeRecipient_withMultipleEntries() external {
        // Arrange - count = 2
        data = abi.encodePacked(uint8(2), chainId1, recipient1, chainId2, recipient2);

        // Act
        remaining = this.initializeRecipientExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        assertEq($.recipientConfig[chainId1], recipient1);
        assertEq($.recipientConfig[chainId2], recipient2);
    }

    /// @notice Test with extra data after entries
    function test_initializeRecipient_withExtraData() external {
        // Arrange
        bytes memory extraData = hex"cafebabe";
        data = abi.encodePacked(uint8(1), chainId1, recipient1, extraData);

        // Act
        remaining = this.initializeRecipientExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Fuzz test for initializeRecipient
    function testFuzz_initializeRecipient(uint256 _chainId, address _recipient) external {
        // Arrange
        data = abi.encodePacked(uint8(1), _chainId, _recipient);

        // Act
        remaining = this.initializeRecipientExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        assertEq($.recipientConfig[_chainId], _recipient);
    }
}
