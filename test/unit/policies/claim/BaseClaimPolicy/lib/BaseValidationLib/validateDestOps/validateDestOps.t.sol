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

/// @title BaseValidationLib.validateDestOps Unit Tests
/// @notice Unit tests for the validateDestOps function
contract BaseValidationLib_validateDestOps_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Results from validateDestOps
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
        presentOpsHash = keccak256("some dest ops");
        noOpsHash = Constants.NO_OPS;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateDestOpsExternal(
        bytes calldata _data,
        uint256 _offset,
        uint256 _targetChainId,
        PolicyConfig _config
    )
        external
        view
        returns (bool, bytes32, uint256)
    {
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexer: msg.sender});
        return BaseValidationLib.validateDestOps(
            $, _data, _offset, _targetChainId, _config, configId, account, testHash
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
    function test_validateDestOps_withModeSkip() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_SKIP);
        data = _buildOpsData(presentOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
        assertEq(newOffset, 32);
    }

    /// @notice Test returns opsHash from calldata when mode is SKIP
    function test_validateDestOps_withModeSkip_returnsOpsHash() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_SKIP);
        data = _buildOpsData(noOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, noOpsHash);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when config requires ops and ops present
    function test_validateDestOps_withModeStorage_requiresOpsAndPresent() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, true); // required = true
        data = _buildOpsData(presentOpsHash); // ops present

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
        assertEq(newOffset, 32);
    }

    /// @notice Test valid=false when config requires ops and ops not present
    function test_validateDestOps_withModeStorage_requiresOpsAndNotPresent() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, true); // required = true
        data = _buildOpsData(noOpsHash); // ops NOT present (NO_OPS)

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertFalse(valid);
    }

    /// @notice Test valid=true when config forbids ops and ops not present
    function test_validateDestOps_withModeStorage_forbidsOpsAndNotPresent() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, false); // required = false (forbids ops)
        data = _buildOpsData(noOpsHash); // ops NOT present (NO_OPS)

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, noOpsHash);
    }

    /// @notice Test valid=false when config forbids ops and ops present
    function test_validateDestOps_withModeStorage_forbidsOpsAndPresent() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, false); // required = false (forbids ops)
        data = _buildOpsData(presentOpsHash); // ops present

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertFalse(valid);
    }

    /// @notice Test with non-zero offset
    function test_validateDestOps_withModeStorage_nonZeroOffset() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, true);

        // Prepend garbage data
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), presentOpsHash);

        // Act - start at offset 32
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 32, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
        assertEq(newOffset, 64);
    }

    /// @notice Test different chain IDs have separate requirements
    function test_validateDestOps_withModeStorage_differentChainIds() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(1, true); // Chain 1 requires ops
        _setupDestOps(137, false); // Chain 137 forbids ops

        bytes memory presentData = _buildOpsData(presentOpsHash);
        bytes memory noOpsData = _buildOpsData(noOpsHash);

        // Act & Assert - chain 1 requires ops
        (valid,,) = this.validateDestOpsExternal(presentData, 0, 1, config);
        assertTrue(valid);
        (valid,,) = this.validateDestOpsExternal(noOpsData, 0, 1, config);
        assertFalse(valid);

        // Chain 137 forbids ops
        (valid,,) = this.validateDestOpsExternal(noOpsData, 0, 137, config);
        assertTrue(valid);
        (valid,,) = this.validateDestOpsExternal(presentData, 0, 137, config);
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateDestOps_withModeCatchall_usesChainIdZero() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_CATCHALL);
        _setupDestOps(0, true); // Store at chainId 0 (catch-all)
        data = _buildOpsData(presentOpsHash);

        // Act - should use chainId 0 regardless of passed chainId
        (valid,,) = this.validateDestOpsExternal(data, 0, 137, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test CATCHALL ignores chain-specific config
    function test_validateDestOps_withModeCatchall_ignoresChainSpecificConfig() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_CATCHALL);
        _setupDestOps(targetChainId, true); // Store at specific chainId
        // Don't set up catch-all (chainId 0) - defaults to false
        data = _buildOpsData(presentOpsHash); // ops present

        // Act
        (valid,,) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert - should fail because catch-all required=false, but ops present
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns valid=true when sub-policy returns true
    function test_validateDestOps_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_DEST_OPS, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);
        data = _buildOpsData(presentOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(opsHash, presentOpsHash);
    }

    /// @notice Test returns valid=false when sub-policy returns false
    function test_validateDestOps_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_DEST_OPS, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);
        data = _buildOpsData(presentOpsHash);

        // Act
        (valid, opsHash, newOffset) = this.validateDestOpsExternal(data, 0, targetChainId, config);

        // Assert
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for STORAGE mode requirement matching
    function testFuzz_validateDestOps_withModeStorage(
        bytes32 _opsHash,
        bool _required,
        uint256 _chainId
    )
        external
    {
        // Arrange
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(_chainId, _required);
        data = _buildOpsData(_opsHash);

        // Act
        (valid,,) = this.validateDestOpsExternal(data, 0, _chainId, config);

        // Assert
        bool hasOps = _opsHash != Constants.NO_OPS;
        bool expected = hasOps == _required;
        assertEq(valid, expected);
    }
}
