// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseValidationLib_Unit_Test } from "../BaseValidationLib.t.sol";

// Libraries
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseValidationLib.validateOriginOps Unit Tests
/// @notice Unit tests for the validateOriginOps function
contract BaseValidationLib_validateOriginOps_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Results from validateOriginOps
    bool internal valid;
    bytes32 internal opsHash;
    uint256 internal newOffset;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Test ops hashes
    bytes32 internal presentOpsHash;
    bytes32 internal noOpsHash;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        presentOpsHash = keccak256("some ops");
        noOpsHash = Constants.NO_OPS;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateOriginOpsExternal(
        bytes calldata _data,
        uint256 _offset,
        uint256 _chainId,
        PolicyConfig _config
    )
        external
        view
        returns (bool, bytes32, uint256)
    {
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexer: msg.sender});
        return BaseValidationLib.validateOriginOps(
            $, _data, _offset, _chainId, _config, configId, account, testHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds calldata with ops hash
    function _buildOpsData(bytes32 _opsHash) internal pure returns (bytes memory) {
        return abi.encodePacked(_opsHash);
    }

    /*//////////////////////////////////////////////////////////////
                            MODE_SKIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns valid=true when mode is SKIP
    function test_validateOriginOps_withModeSkip() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_SKIP);
        data = _buildOpsData(presentOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
        assertEq(newOffset, 32);
    }

    /// @notice Test returns opsHash from calldata when mode is SKIP
    function test_validateOriginOps_withModeSkip_returnsOpsHash() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_SKIP);
        data = _buildOpsData(noOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, noOpsHash);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when ops required and ops present
    function test_validateOriginOps_withModeStorage_requiredAndPresent() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, true); // required = true
        data = _buildOpsData(presentOpsHash); // ops present

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
        assertEq(newOffset, 32);
    }

    /// @notice Test valid=false when ops required and ops not present
    function test_validateOriginOps_withModeStorage_requiredAndNotPresent() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, true); // required = true
        data = _buildOpsData(noOpsHash); // ops NOT present (NO_OPS)

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertFalse(valid);
    }

    /// @notice Test valid=true when ops not required and ops not present
    function test_validateOriginOps_withModeStorage_forbidsOpsAndNotPresent() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, false); // required = false
        data = _buildOpsData(noOpsHash); // ops NOT present (NO_OPS)

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, noOpsHash);
    }

    /// @notice Test valid=false when ops not required and ops present
    function test_validateOriginOps_withModeStorage_forbidsOpsAndPresent() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, false); // required = false
        data = _buildOpsData(presentOpsHash); // ops present

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertFalse(valid);
    }

    /// @notice Test with non-zero offset
    function test_validateOriginOps_withModeStorage_nonZeroOffset() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, true);

        // Prepend garbage data
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), presentOpsHash);

        // Act - start at offset 32
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 32, chainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
        assertEq(newOffset, 64);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateOriginOps_withModeCatchall_usesChainIdZero() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_CATCHALL);
        _setupOriginOps(0, true); // Store at chainId 0 (catch-all)
        data = _buildOpsData(presentOpsHash);

        // Act - should use chainId 0 regardless of passed chainId
        (valid,,) = this.validateOriginOpsExternal(data, 0, 137, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test CATCHALL ignores chain-specific config
    function test_validateOriginOps_withModeCatchall_ignoresChainSpecificConfig() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_CATCHALL);
        _setupOriginOps(chainId, true); // Store at specific chainId
        // Don't set up catch-all (chainId 0) - defaults to false
        data = _buildOpsData(presentOpsHash); // ops present

        // Act
        (valid,,) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert - should fail because catch-all required=false, but ops present
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns valid=true when sub-policy returns true
    function test_validateOriginOps_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_ORIGIN_OPS, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);
        data = _buildOpsData(presentOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
    }

    /// @notice Test returns valid=false when sub-policy returns false
    function test_validateOriginOps_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_ORIGIN_OPS, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);
        data = _buildOpsData(presentOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for STORAGE mode requirement matching
    function testFuzz_validateOriginOps_withModeStorage(bytes32 _opsHash, bool _required) external {
        // Arrange
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, _required);
        data = _buildOpsData(_opsHash);

        // Act
        (valid,,) = this.validateOriginOpsExternal(data, 0, chainId, config);

        // Assert
        bool hasOps = _opsHash != Constants.NO_OPS;
        bool expected = hasOps == _required;
        assertEq(valid, expected);
    }
}
