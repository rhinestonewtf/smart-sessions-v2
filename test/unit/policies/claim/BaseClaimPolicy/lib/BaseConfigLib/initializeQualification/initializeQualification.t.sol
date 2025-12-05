// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

/// @title BaseConfigLib.initializeQualification Unit Tests
/// @notice Unit tests for the initializeQualification function
contract BaseConfigLib_initializeQualification_Unit_Test is BaseConfigLib_Unit_Test {
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

    /// @notice Test arbiters
    address internal arbiter1;
    address internal arbiter2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = address(0x1234);
        chainId1 = 1;
        chainId2 = 137;
        arbiter1 = address(0xA1);
        arbiter2 = address(0xA2);
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test with calldata
    function initializeQualificationExternal(
        ConfigId _configId,
        address _account,
        bytes calldata _initData
    )
        external
        returns (bytes memory)
    {
        BasePolicyStorage storage $ = _configId.getStorage(_account);
        bytes calldata _remaining = $.initializeQualification(_initData);
        return _remaining;
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds a minimal valid qualification entry
    /// @param _chainId The chain ID for the entry
    /// @param _arbiter The arbiter address
    /// @return entryData The encoded entry
    function _buildValidEntry(
        uint256 _chainId,
        address _arbiter
    )
        internal
        pure
        returns (bytes memory entryData)
    {
        // Header: chainId (32) + arbiter (20) + useArbiterHash (1) + rootNodeIndex (1)
        // Rules: ruleCount (1) + 1 rule (42 bytes)
        // Nodes: packedNodesCount (1) + 1 node (32 bytes)
        entryData = abi.encodePacked(
            _chainId, // chainId
            _arbiter, // arbiter
            uint8(0), // useArbiterHash = false
            uint8(0), // rootNodeIndex = 0
            uint8(1), // ruleCount = 1
            // Rule: condition (1) + offset (8) + length (1) + ref (32) = 42 bytes
            uint8(ParamCondition.EQUAL),
            uint64(0), // offset
            uint8(32), // length
            bytes32(0), // ref
            uint8(1), // packedNodesCount = 1
            uint256(0) // packedNode (leaf node)
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with zero entries
    function test_initializeQualification_withZeroEntries() external {
        // Arrange - count = 0
        data = abi.encodePacked(uint8(0));

        // Act
        remaining = this.initializeQualificationExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);
    }

    /// @notice Test with single entry
    function test_initializeQualification_withSingleEntry() external {
        // Arrange - count = 1 + valid entry
        bytes memory entry = _buildValidEntry(chainId1, arbiter1);
        data = abi.encodePacked(uint8(1), entry);

        // Act
        remaining = this.initializeQualificationExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ = configId.getStorage(account);
        assertEq($.qualificationConfig[chainId1][arbiter1].rules.rules.length, 1);
        assertEq($.qualificationConfig[chainId1][arbiter1].rules.packedNodes.length, 1);
    }

    /// @notice Test with multiple entries
    function test_initializeQualification_withMultipleEntries() external {
        // Arrange - count = 2
        bytes memory entry1 = _buildValidEntry(chainId1, arbiter1);
        bytes memory entry2 = _buildValidEntry(chainId2, arbiter2);
        data = abi.encodePacked(uint8(2), entry1, entry2);

        // Act
        remaining = this.initializeQualificationExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 0);

        // Verify storage
        BasePolicyStorage storage $ = configId.getStorage(account);
        assertEq($.qualificationConfig[chainId1][arbiter1].rules.rules.length, 1);
        assertEq($.qualificationConfig[chainId2][arbiter2].rules.rules.length, 1);
    }

    /// @notice Test with extra data after entries
    function test_initializeQualification_withExtraData() external {
        // Arrange
        bytes memory entry = _buildValidEntry(chainId1, arbiter1);
        bytes memory extraData = hex"deadbeef";
        data = abi.encodePacked(uint8(1), entry, extraData);

        // Act
        remaining = this.initializeQualificationExternal(configId, account, data);

        // Assert
        assertEq(remaining.length, 4);
        assertEq(keccak256(remaining), keccak256(extraData));
    }

    /// @notice Test reverts when ruleCount is zero
    function test_initializeQualification_revertsWhen_ruleCountIsZero() external {
        // Arrange - entry with ruleCount = 0 but packedNodesCount = 1
        data = abi.encodePacked(
            uint8(1), // count
            chainId1, // chainId
            arbiter1, // arbiter
            uint8(0), // useArbiterHash
            uint8(0), // rootNodeIndex
            uint8(0), // ruleCount = 0 (invalid!)
            uint8(1), // packedNodesCount = 1
            uint256(0) // packedNode
        );

        // Act & Assert
        vm.expectRevert(BaseConfigLib.QualificationRulesNotSet.selector);
        this.initializeQualificationExternal(configId, account, data);
    }

    /// @notice Test reverts when packedNodesLength is zero
    function test_initializeQualification_revertsWhen_packedNodesLengthIsZero() external {
        // Arrange - entry with ruleCount = 1 but packedNodesCount = 0
        data = abi.encodePacked(
            uint8(1), // count
            chainId1, // chainId
            arbiter1, // arbiter
            uint8(0), // useArbiterHash
            uint8(0), // rootNodeIndex
            uint8(1), // ruleCount = 1
            // Rule: condition (1) + offset (8) + length (1) + ref (32) = 42 bytes
            uint8(ParamCondition.EQUAL),
            uint64(0),
            uint8(32),
            bytes32(0),
            uint8(0) // packedNodesCount = 0 (invalid!)
        );

        // Act & Assert
        vm.expectRevert(BaseConfigLib.QualificationRulesNotSet.selector);
        this.initializeQualificationExternal(configId, account, data);
    }
}
