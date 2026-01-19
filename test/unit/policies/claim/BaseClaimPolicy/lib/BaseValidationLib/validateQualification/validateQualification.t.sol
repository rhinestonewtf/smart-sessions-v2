// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseValidationLib_Unit_Test } from "../BaseValidationLib.t.sol";

// Libraries
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import {
    ParamRules,
    ParamRule,
    QualificationRulesStorage
} from "@policies/claim/base/types/BaseDataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";
import { MockArbiter } from "@mocks/MockArbiter.sol";

/// @title BaseValidationLib.validateQualification Unit Tests
/// @notice Unit tests for the validateQualification function
contract BaseValidationLib_validateQualification_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Results from validateQualification
    bool internal valid;
    bytes32 internal qualificationHash;
    uint256 internal newOffset;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Mock arbiter for hash computation tests
    MockArbiter internal mockArbiter;

    /// @notice Test qualification data
    bytes internal qualificationData;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        mockArbiter = new MockArbiter();
        arbiter = address(mockArbiter);
        qualificationData = hex"deadbeefcafe";
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateQualificationExternal(
        bytes calldata _data,
        uint256 _offset,
        uint256 _chainId,
        address _arbiter,
        PolicyConfig _config
    )
        external
        view
        returns (bool, bytes32, uint256)
    {
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexer: msg.sender});
        return BaseValidationLib.validateQualification(
            $, _data, _offset, _chainId, _arbiter, _config, configId, account, testHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds qualification calldata for STORAGE mode
    /// @dev Format: [dataLength: 32][qualificationData: length]
    function _buildQualificationData(bytes memory _qualData) internal pure returns (bytes memory) {
        return abi.encodePacked(uint256(_qualData.length), _qualData);
    }

    /// @notice Builds qualification calldata for SUBPOLICY mode
    /// @dev Format: [flags: 1][dataLength: 32][qualificationData: length]
    function _buildQualificationDataWithFlags(
        bytes memory _qualData,
        uint8 _flags
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(_flags, uint256(_qualData.length), _qualData);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when no rules configured
    function test_validateQualification_withModeStorage_noRulesConfigured() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        _setupEmptyQualificationRules(chainId, arbiter, false);
        data = _buildQualificationData(qualificationData);

        // Act
        (valid, qualificationHash, newOffset) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, keccak256(qualificationData));
    }

    /// @notice Test valid=true when rules pass
    function test_validateQualification_withModeStorage_rulesPass() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory matchingData = abi.encodePacked(bytes32(uint256(42)));
        _setupEqualRule(chainId, arbiter, false, bytes32(uint256(42)));
        data = _buildQualificationData(matchingData);

        // Act
        (valid, qualificationHash, newOffset) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, keccak256(matchingData));
    }

    /// @notice Test valid=false when rules fail
    function test_validateQualification_withModeStorage_rulesFail() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory nonMatchingData = abi.encodePacked(bytes32(uint256(99))); // Doesn't match 42
        _setupEqualRule(chainId, arbiter, false, bytes32(uint256(42)));
        data = _buildQualificationData(nonMatchingData);

        // Act
        (valid, qualificationHash, newOffset) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertFalse(valid);
        assertEq(qualificationHash, bytes32(0));
    }

    /// @notice Test uses keccak256 when useArbiterHash is false
    function test_validateQualification_withModeStorage_usesKeccak256() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        _setupEmptyQualificationRules(chainId, arbiter, false); // useArbiterHash = false
        data = _buildQualificationData(qualificationData);

        // Act
        (valid, qualificationHash,) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, keccak256(qualificationData));
    }

    /// @notice Test calls arbiter.qualificationHash when useArbiterHash is true
    function test_validateQualification_withModeStorage_usesArbiterHash() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        _setupEmptyQualificationRules(chainId, arbiter, true); // useArbiterHash = true
        bytes32 expectedHash = keccak256("arbiter computed hash");
        mockArbiter.setQualificationHash(expectedHash);
        data = _buildQualificationData(qualificationData);

        // Act
        (valid, qualificationHash,) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, expectedHash);
    }

    /// @notice Test with non-zero offset
    function test_validateQualification_withModeStorage_nonZeroOffset() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        _setupEmptyQualificationRules(chainId, arbiter, false);

        bytes memory qualData = _buildQualificationData(qualificationData);
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), qualData); // Prepend garbage

        // Act - start at offset 32
        (valid, qualificationHash, newOffset) =
            this.validateQualificationExternal(data, 32, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, keccak256(qualificationData));
        assertEq(newOffset, 32 + qualData.length);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateQualification_withModeCatchall_usesChainIdZero() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_CATCHALL);
        _setupEmptyQualificationRules(0, arbiter, false); // Store at chainId 0
        data = _buildQualificationData(qualificationData);

        // Act - should use chainId 0 regardless of passed chainId
        (valid,,) = this.validateQualificationExternal(data, 0, 137, arbiter, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test CATCHALL ignores chain-specific config with failing rules
    function test_validateQualification_withModeCatchall_ignoresChainSpecificRules() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_CATCHALL);

        // Set up failing rules at specific chainId
        bytes memory matchingData = abi.encodePacked(bytes32(uint256(99))); // Won't match 42
        _setupEqualRule(chainId, arbiter, false, bytes32(uint256(42)));

        // Set up passing (empty) rules at chainId 0
        _setupEmptyQualificationRules(0, arbiter, false);

        data = _buildQualificationData(matchingData);

        // Act - should use chainId 0 rules (empty = pass), not chainId rules (would fail)
        (valid,,) = this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns valid=true when sub-policy returns true
    function test_validateQualification_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_QUALIFICATION, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);
        data = _buildQualificationDataWithFlags(qualificationData, 0); // flags = 0, use keccak256

        // Act
        (valid, qualificationHash,) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, keccak256(qualificationData));
    }

    /// @notice Test returns valid=false when sub-policy returns false
    function test_validateQualification_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_QUALIFICATION, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);
        data = _buildQualificationDataWithFlags(qualificationData, 0);

        // Act
        (valid, qualificationHash,) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertFalse(valid);
        assertEq(qualificationHash, bytes32(0));
    }

    /// @notice Test uses keccak256 when flags bit 0 is not set
    function test_validateQualification_withModeSubPolicy_usesKeccak256() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_QUALIFICATION, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);
        data = _buildQualificationDataWithFlags(qualificationData, 0); // flags = 0

        // Act
        (valid, qualificationHash,) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, keccak256(qualificationData));
    }

    /// @notice Test uses arbiter hash when flags bit 0 is set
    function test_validateQualification_withModeSubPolicy_usesArbiterHash() external {
        // Arrange
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_QUALIFICATION, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);
        bytes32 expectedHash = keccak256("arbiter computed hash");
        mockArbiter.setQualificationHash(expectedHash);
        data = _buildQualificationDataWithFlags(qualificationData, 1); // flags = 1 (useArbiterHash)

        // Act
        (valid, qualificationHash,) =
            this.validateQualificationExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(qualificationHash, expectedHash);
    }
}
