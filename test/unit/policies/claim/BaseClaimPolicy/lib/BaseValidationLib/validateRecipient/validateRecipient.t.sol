// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseValidationLib_Unit_Test } from "../BaseValidationLib.t.sol";

// Libraries
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseValidationLib.validateRecipient Unit Tests
/// @notice Unit tests for the validateRecipient function
contract BaseValidationLib_validateRecipient_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from validateRecipient
    bool internal result;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Additional test recipients
    address internal recipient2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        recipient2 = address(0xdd2);
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateRecipientExternal(
        address _recipient,
        uint256 _targetChainId,
        PolicyConfig _config
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexer: msg.sender});
        return BaseValidationLib.validateRecipient(
            $, _recipient, _targetChainId, _config, configId, account, testHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                            MODE_SKIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when mode is SKIP
    function test_validateRecipient_withModeSkip() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_SKIP);

        // Act
        result = this.validateRecipientExternal(recipient, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when mode is SKIP regardless of recipient
    function testFuzz_validateRecipient_withModeSkip(
        address _recipient,
        uint256 _chainId
    )
        external
    {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_SKIP);

        // Act
        result = this.validateRecipientExternal(_recipient, _chainId, config);

        // Assert
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when recipient matches stored value
    function test_validateRecipient_withModeStorage_recipientMatches() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);

        // Act
        result = this.validateRecipientExternal(recipient, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when recipient does not match stored value
    function test_validateRecipient_withModeStorage_recipientDoesNotMatch() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);

        // Act
        result = this.validateRecipientExternal(recipient2, targetChainId, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns true for any recipient when stored value is ANY_ADDRESS
    function test_validateRecipient_withModeStorage_anyAddressWildcard() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, ANY_ADDRESS);

        // Act & Assert - any recipient should pass
        assertTrue(this.validateRecipientExternal(recipient, targetChainId, config));
        assertTrue(this.validateRecipientExternal(recipient2, targetChainId, config));
        assertTrue(this.validateRecipientExternal(address(0), targetChainId, config));
        assertTrue(this.validateRecipientExternal(address(0xDEAD), targetChainId, config));
    }

    /// @notice Test returns false when no stored value for chainId
    function test_validateRecipient_withModeStorage_noStoredValue() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        // No recipient set up for targetChainId

        // Act
        result = this.validateRecipientExternal(recipient, targetChainId, config);

        // Assert - default value is address(0), so only address(0) would match
        assertFalse(result);
    }

    /// @notice Test with different chain IDs
    function test_validateRecipient_withModeStorage_differentChainIds() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(1, recipient);
        _setupRecipient(137, recipient2);

        // Act & Assert
        assertTrue(this.validateRecipientExternal(recipient, 1, config));
        assertFalse(this.validateRecipientExternal(recipient2, 1, config));
        assertTrue(this.validateRecipientExternal(recipient2, 137, config));
        assertFalse(this.validateRecipientExternal(recipient, 137, config));
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateRecipient_withModeCatchall_usesChainIdZero() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_CATCHALL);
        _setupRecipient(0, recipient); // Store at chainId 0 (catch-all)

        // Act - should pass for any chainId
        result = this.validateRecipientExternal(recipient, 1, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test CATCHALL ignores chain-specific config
    function test_validateRecipient_withModeCatchall_ignoresChainSpecificConfig() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_CATCHALL);
        _setupRecipient(targetChainId, recipient); // Store at specific chainId
        // Don't set up catch-all

        // Act
        result = this.validateRecipientExternal(recipient, targetChainId, config);

        // Assert - should fail because catch-all (chainId 0) is not set
        assertFalse(result);
    }

    /// @notice Test CATCHALL with ANY_ADDRESS wildcard
    function test_validateRecipient_withModeCatchall_anyAddressWildcard() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_CATCHALL);
        _setupRecipient(0, ANY_ADDRESS);

        // Act & Assert - any recipient on any chain should pass
        assertTrue(this.validateRecipientExternal(recipient, 1, config));
        assertTrue(this.validateRecipientExternal(recipient2, 137, config));
        assertTrue(this.validateRecipientExternal(address(0xDEAD), 42_161, config));
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when sub-policy returns true
    function test_validateRecipient_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_RECIPIENT, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);

        // Act
        result = this.validateRecipientExternal(recipient, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when sub-policy returns false
    function test_validateRecipient_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_RECIPIENT, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);

        // Act
        result = this.validateRecipientExternal(recipient, targetChainId, config);

        // Assert
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for STORAGE mode matching
    function testFuzz_validateRecipient_withModeStorage(
        address _recipient,
        address _storedRecipient,
        uint256 _chainId
    )
        external
    {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(_chainId, _storedRecipient);

        // Act
        result = this.validateRecipientExternal(_recipient, _chainId, config);

        // Assert
        bool expected = _recipient == _storedRecipient || _storedRecipient == ANY_ADDRESS;
        assertEq(result, expected);
    }
}
