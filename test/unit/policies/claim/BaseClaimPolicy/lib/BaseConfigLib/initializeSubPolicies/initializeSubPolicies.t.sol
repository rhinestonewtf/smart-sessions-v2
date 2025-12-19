// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_EXPIRY
} from "@policies/claim/base/types/BaseDataTypes.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

/// @title BaseConfigLib.initializeSubPolicies Unit Tests
/// @notice Unit tests for the initializeSubPolicies function
contract BaseConfigLib_initializeSubPolicies_Unit_Test is BaseConfigLib_Unit_Test {
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

    /// @notice Mock sub-policies
    MockSubPolicy internal subPolicy1;
    MockSubPolicy internal subPolicy2;

    /// @notice Test init data
    bytes internal initData1;
    bytes internal initData2;

    /// @notice Mode config with SUBPOLICY mode for ARBITER field
    PolicyConfig internal modeConfigWithSubPolicy;

    /// @notice Mode config with STORAGE mode for ARBITER field
    PolicyConfig internal modeConfigWithStorage;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = address(0x1234);

        // Deploy mock sub-policies
        subPolicy1 = new MockSubPolicy();
        subPolicy2 = new MockSubPolicy();

        initData1 = hex"aabbccdd";
        initData2 = hex"11223344";

        // ARBITER field (0) with SUBPOLICY mode (3) = bits 0-1 = 11 = 0x03
        modeConfigWithSubPolicy = PolicyConfig.wrap(0x00000003);

        // ARBITER field (0) with STORAGE mode (1) = bits 0-1 = 01 = 0x01
        modeConfigWithStorage = PolicyConfig.wrap(0x00000001);
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeSubPoliciesExternal(
        ConfigId _configId,
        address _account,
        PolicyConfig _modeConfig,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account, msg.sender);
        bytes calldata _remaining =
            $.initializeSubPolicies(_initData, _modeConfig, _account, _configId);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero sub-policies
    function test_initializeSubPolicies_withZeroSubPolicies() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining =
            this.initializeSubPoliciesExternal(configId, account, modeConfigWithSubPolicy, data);

        // Assert
        assertEq(remaining.length, 0);
    }

    /// @notice Test with single sub-policy with no init data
    function test_initializeSubPolicies_withSingleSubPolicyNoInitData() external {
        // Arrange - count = 1, fieldId = ARBITER, address, length = 0
        data = abi.encodePacked(
            uint8(1), // count
            uint8(FIELD_ARBITER), // fieldId
            address(subPolicy1), // policy address
            uint256(0) // init data length
        );

        // Act
        remaining =
            this.initializeSubPoliciesExternal(configId, account, modeConfigWithSubPolicy, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.subPolicies[FIELD_ARBITER], address(subPolicy1));

        // Verify initializeWithMultiplexer was called
        assertEq(subPolicy1.initializeWithMultiplexerCallCount(), 1);
    }

    /// @notice Test with single sub-policy with init data
    function test_initializeSubPolicies_withSingleSubPolicyWithInitData() external {
        // Arrange - count = 1, fieldId = ARBITER, address, length, initData
        data = abi.encodePacked(
            uint8(1), // count
            uint8(FIELD_ARBITER), // fieldId
            address(subPolicy1), // policy address
            uint256(initData1.length), // init data length
            initData1 // init data
        );

        // Act
        remaining =
            this.initializeSubPoliciesExternal(configId, account, modeConfigWithSubPolicy, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.subPolicies[FIELD_ARBITER], address(subPolicy1));

        // Verify initializeWithMultiplexer was called with correct data
        assertEq(subPolicy1.initializeWithMultiplexerCallCount(), 1);
        assertEq(keccak256(subPolicy1.lastInitData()), keccak256(initData1));
    }

    /// @notice Test with multiple sub-policies
    function test_initializeSubPolicies_withMultipleSubPolicies() external {
        // Setup mode config with SUBPOLICY for both ARBITER and EXPIRY
        // ARBITER (0) = 11, EXPIRY (1) = 11 -> 0x0F
        PolicyConfig multiSubPolicyConfig = PolicyConfig.wrap(0x0000000F);

        // Arrange - count = 2
        data = abi.encodePacked(
            uint8(2), // count
            uint8(FIELD_ARBITER), // fieldId 1
            address(subPolicy1), // policy address 1
            uint256(initData1.length), // init data length 1
            initData1, // init data 1
            uint8(FIELD_EXPIRY), // fieldId 2
            address(subPolicy2), // policy address 2
            uint256(initData2.length), // init data length 2
            initData2 // init data 2
        );

        // Act
        remaining =
            this.initializeSubPoliciesExternal(configId, account, multiSubPolicyConfig, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: address(this) });
        assertEq($.subPolicies[FIELD_ARBITER], address(subPolicy1));
        assertEq($.subPolicies[FIELD_EXPIRY], address(subPolicy2));

        // Verify both were initialized
        assertEq(subPolicy1.initializeWithMultiplexerCallCount(), 1);
        assertEq(subPolicy2.initializeWithMultiplexerCallCount(), 1);
    }

    /// @notice Test with extra data after sub-policies
    function test_initializeSubPolicies_withExtraData() external {
        // Arrange
        bytes memory extraData = hex"deadbeef";
        data = abi.encodePacked(
            uint8(1), // count
            uint8(FIELD_ARBITER), // fieldId
            address(subPolicy1), // policy address
            uint256(initData1.length), // init data length
            initData1, // init data
            extraData
        );

        // Act
        remaining =
            this.initializeSubPoliciesExternal(configId, account, modeConfigWithSubPolicy, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Test configId and account are passed correctly to initializeWithMultiplexer
    function test_initializeSubPolicies_passesConfigIdAndAccount() external {
        // Arrange
        data = abi.encodePacked(
            uint8(1), // count
            uint8(FIELD_ARBITER), // fieldId
            address(subPolicy1), // policy address
            uint256(0) // init data length
        );

        // Act
        remaining =
            this.initializeSubPoliciesExternal(configId, account, modeConfigWithSubPolicy, data);

        // Assert - verify configId and account were passed
        assertEq(ConfigId.unwrap(subPolicy1.lastConfigId()), ConfigId.unwrap(configId));
        assertEq(subPolicy1.lastAccount(), account);
    }

    /// @notice Test reverts when fieldId mode is not SUBPOLICY
    function test_initializeSubPolicies_revertsWhen_modeIsNotSubPolicy() external {
        // Arrange - use modeConfig with STORAGE mode for ARBITER
        data = abi.encodePacked(
            uint8(1), // count
            uint8(FIELD_ARBITER), // fieldId
            address(subPolicy1), // policy address
            uint256(0) // init data length
        );

        // Act & Assert
        vm.expectRevert(BaseConfigLib.InvalidMode.selector);
        this.initializeSubPoliciesExternal(configId, account, modeConfigWithStorage, data);
    }
}
