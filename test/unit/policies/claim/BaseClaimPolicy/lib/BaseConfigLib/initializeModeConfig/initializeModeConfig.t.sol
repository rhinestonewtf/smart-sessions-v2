// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseConfigLib.initializeModeConfig Unit Tests
/// @notice Unit tests for the initializeModeConfig function
contract BaseConfigLib_initializeModeConfig_Unit_Test is BaseConfigLib_Unit_Test {
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

    /// @notice Result PolicyConfig
    PolicyConfig internal resultConfig;

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
    function initializeModeConfigExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (PolicyConfig, bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        (PolicyConfig _config, bytes calldata _remaining) = $.initializeModeConfig(_initData);
        return (_config, _remaining);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializing with valid 4-byte config
    function test_initializeModeConfig_withValidConfig() external {
        // Arrange - ARBITER=STORAGE(01)
        data = abi.encodePacked(uint32(0x00000001));

        // Act
        (resultConfig, remaining) = this.initializeModeConfigExternal(configId, account, data);

        // Assert
        assertEq(PolicyConfig.unwrap(resultConfig), 0x00000001);
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: address(this) });
        assertEq(PolicyConfig.unwrap($.modeConfig), 0x00000001);
    }

    /// @notice Test initializing with all zeros
    function test_initializeModeConfig_withAllZeros() external {
        // Arrange
        data = abi.encodePacked(uint32(0x00000000));

        // Act
        (resultConfig, remaining) = this.initializeModeConfigExternal(configId, account, data);

        // Assert
        assertEq(PolicyConfig.unwrap(resultConfig), 0x00000000);
        assertEq(remaining.length, 0);
    }

    /// @notice Test initializing with all fields enabled
    function test_initializeModeConfig_withAllFieldsEnabled() external {
        // Arrange - all fields set to STORAGE(01)
        // 10 fields * 2 bits = 20 bits, all set to 01 = 0x55555
        data = abi.encodePacked(uint32(0x00055555));

        // Act
        (resultConfig, remaining) = this.initializeModeConfigExternal(configId, account, data);

        // Assert
        assertEq(PolicyConfig.unwrap(resultConfig), 0x00055555);
    }

    /// @notice Test remaining data is returned correctly
    function test_initializeModeConfig_withExtraData() external {
        // Arrange - config + extra data
        bytes memory extraData = hex"deadbeef";
        data = abi.encodePacked(uint32(0x00000001), extraData);

        // Act
        (resultConfig, remaining) = this.initializeModeConfigExternal(configId, account, data);

        // Assert
        assertEq(PolicyConfig.unwrap(resultConfig), 0x00000001);
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Fuzz test for initializeModeConfig
    function testFuzz_initializeModeConfig(uint32 _modeConfig) external {
        // Exclude the invalid combination rejected by initializeModeConfig: chain-aware (STORAGE
        // or SUBPOLICY) destOps (field 7, bits 14-15) without any target check (bits 6-7, 8-9,
        // 10-11, 18-19).
        uint32 maskTargetChecks =
            (uint32(0x3) << 6) | (uint32(0x3) << 8) | (uint32(0x3) << 10) | (uint32(0x3) << 18);
        uint8 destOpsMode = uint8((_modeConfig >> 14) & 0x3);
        bool destOpsChainAware = destOpsMode == 1 || destOpsMode == 3;
        vm.assume(!(destOpsChainAware && (_modeConfig & maskTargetChecks) == 0));

        // Arrange
        data = abi.encodePacked(_modeConfig);

        // Act
        (resultConfig, remaining) = this.initializeModeConfigExternal(configId, account, data);

        // Assert
        assertEq(PolicyConfig.unwrap(resultConfig), _modeConfig);
        assertEq(remaining.length, 0);
    }
}
