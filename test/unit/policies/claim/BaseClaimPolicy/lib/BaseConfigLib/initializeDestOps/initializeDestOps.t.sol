// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseConfigLib.initializeDestOps Unit Tests
/// @notice Unit tests for the initializeDestOps function
contract BaseConfigLib_initializeDestOps_Unit_Test is BaseConfigLib_Unit_Test {
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
    function initializeDestOpsExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        bytes calldata _remaining = $.initializeDestOps(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero entries
    function test_initializeDestOps_withZeroEntries() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining = this.initializeDestOpsExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);
    }

    /// @notice Test with single entry required=true
    function test_initializeDestOps_withRequiredTrue() external {
        // Arrange - count = 1, chainId1, required=true
        data = abi.encodePacked(uint8(1), chainId1, uint8(1));

        // Act
        remaining = this.initializeDestOpsExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.destOpsConfig[chainId1], true);
    }

    /// @notice Test with single entry required=false
    function test_initializeDestOps_withRequiredFalse() external {
        // Arrange - count = 1, chainId1, required=false
        data = abi.encodePacked(uint8(1), chainId1, uint8(0));

        // Act
        remaining = this.initializeDestOpsExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.destOpsConfig[chainId1], false);
    }

    /// @notice Test with multiple entries
    function test_initializeDestOps_withMultipleEntries() external {
        // Arrange - count = 2
        data = abi.encodePacked(uint8(2), chainId1, uint8(1), chainId2, uint8(0));

        // Act
        remaining = this.initializeDestOpsExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.destOpsConfig[chainId1], true);
        assertEq($.destOpsConfig[chainId2], false);
    }

    /// @notice Test with extra data after entries
    function test_initializeDestOps_withExtraData() external {
        // Arrange
        bytes memory extraData = hex"cafebabe";
        data = abi.encodePacked(uint8(1), chainId1, uint8(1), extraData);

        // Act
        remaining = this.initializeDestOpsExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Fuzz test for initializeDestOps
    function testFuzz_initializeDestOps(uint256 _chainId, bool _required) external {
        // Arrange
        data = abi.encodePacked(uint8(1), _chainId, _required);

        // Act
        remaining = this.initializeDestOpsExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.destOpsConfig[_chainId], _required);
    }
}
