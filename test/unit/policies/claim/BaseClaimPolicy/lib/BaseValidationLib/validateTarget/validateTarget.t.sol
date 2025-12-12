// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseValidationLib_Unit_Test } from "../BaseValidationLib.t.sol";

// Libraries
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseValidationLib.validateTarget Unit Tests
/// @notice Unit tests for the validateTarget function
contract BaseValidationLib_validateTarget_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;
    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Results from validateTarget
    bool internal valid;
    bytes32 internal targetHash;
    uint256 internal returnedTargetChainId;
    uint256 internal newOffset;

    /// @notice Mock sub-policy
    MockSubPolicy internal mockSubPolicy;

    /// @notice Test target values
    uint256 internal fillExpiry;
    uint256 internal amount1;

    /// @notice Pre-computed tokenOutHash for tests
    bytes32 internal precomputedTokenOutHash;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        fillExpiry = 1000;
        amount1 = 1 ether;
        precomputedTokenOutHash = keccak256("tokenOutHash");
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateTargetExternal(
        bytes calldata _data,
        uint256 _offset,
        PolicyConfig _config
    )
        external
        view
        returns (bool, bytes32, uint256, uint256)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return
            BaseValidationLib.validateTarget(
                $, _data, _offset, _config, configId, account, testHash
            );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds target calldata with pre-computed tokenOutHash
    /// @dev Format: [recipient: 20][targetChainId: 32][fillExpiry: 32][tokenOutHash: 32]
    function _buildTargetDataWithTokenOutHash(
        address _recipient,
        uint256 _targetChainId,
        uint256 _fillExpiry,
        bytes32 _tokenOutHash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes20(_recipient), _targetChainId, _fillExpiry, _tokenOutHash);
    }

    /// @notice Builds target calldata with inline tokenOut array
    /// @dev Format: [recipient: 20][targetChainId: 32][fillExpiry: 32][tokenOutLength:
    /// 1][tokenOut...]
    function _buildTargetDataWithTokenOut(
        address _recipient,
        uint256 _targetChainId,
        uint256 _fillExpiry,
        address _token,
        uint256 _amount
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes20(_recipient),
            _targetChainId,
            _fillExpiry,
            uint8(1), // tokenOut length
            uint256(uint160(_token)), // token (left-padded)
            _amount
        );
    }

    /// @notice Builds target calldata with empty tokenOut array
    function _buildTargetDataWithEmptyTokenOut(
        address _recipient,
        uint256 _targetChainId,
        uint256 _fillExpiry
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes20(_recipient),
            _targetChainId,
            _fillExpiry,
            uint8(0) // empty tokenOut array
        );
    }

    /// @notice Computes expected target hash
    function _computeExpectedTargetHash(
        address _recipient,
        bytes32 _tokenOutHash,
        uint256 _targetChainId,
        uint256 _fillExpiry
    )
        internal
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashTargetAttributesRaw(
            _recipient, _tokenOutHash, _targetChainId, _fillExpiry
        );
    }

    /*//////////////////////////////////////////////////////////////
                    RECIPIENT_IS_SPONSOR TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when recipient equals account (sponsor)
    function test_validateTarget_withRecipientIsSponsor_recipientEqualsAccount() external {
        // Arrange - RECIPIENT_IS_SPONSOR enabled
        config = _buildConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        data = _buildTargetDataWithTokenOutHash(
            account, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertTrue(valid);
        assertEq(returnedTargetChainId, targetChainId);

        bytes32 expectedHash =
            _computeExpectedTargetHash(account, precomputedTokenOutHash, targetChainId, fillExpiry);
        assertEq(targetHash, expectedHash);
    }

    /// @notice Test valid=false when recipient does not equal account
    function test_validateTarget_withRecipientIsSponsor_recipientNotEqualsAccount() external {
        // Arrange - RECIPIENT_IS_SPONSOR enabled, but recipient != account
        config = _buildConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertFalse(valid);
        assertEq(targetHash, bytes32(0));
        assertEq(returnedTargetChainId, 0);
        assertEq(newOffset, 0);
    }

    /*//////////////////////////////////////////////////////////////
                         RECIPIENT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when recipient passes storage validation
    function test_validateTarget_withRecipient_recipientPasses() external {
        // Arrange - RECIPIENT enabled with storage mode
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);
        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertTrue(valid);
        assertEq(returnedTargetChainId, targetChainId);
    }

    /// @notice Test valid=false when recipient fails storage validation
    function test_validateTarget_withRecipient_recipientFails() external {
        // Arrange - RECIPIENT enabled, but recipient not in storage
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, address(0xBEEF)); // Different recipient in storage
        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                        FILL_EXPIRY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when fillExpiry passes validation
    function test_validateTarget_withFillExpiry_fillExpiryPasses() external {
        // Arrange - FILL_EXPIRY enabled
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, 500, 1500); // fillExpiry=1000 is within bounds
        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test valid=false when fillExpiry fails validation
    function test_validateTarget_withFillExpiry_fillExpiryFails() external {
        // Arrange - FILL_EXPIRY enabled, but fillExpiry out of bounds
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, 2000, 3000); // fillExpiry=1000 is out of bounds
        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                          TOKEN_OUT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test valid=true when tokenOut passes validation
    function test_validateTarget_withTokenOut_tokenOutPasses() external {
        // Arrange - TOKEN_OUT enabled
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1);
        data = _buildTargetDataWithTokenOut(recipient, targetChainId, fillExpiry, token1, amount1);

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertTrue(valid);
        assertEq(returnedTargetChainId, targetChainId);
        assertEq(newOffset, data.length);
    }

    /// @notice Test valid=false when tokenOut fails validation
    function test_validateTarget_withTokenOut_tokenOutFails() external {
        // Arrange - TOKEN_OUT enabled, but token not whitelisted
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token2); // Different token whitelisted
        data = _buildTargetDataWithTokenOut(recipient, targetChainId, fillExpiry, token1, amount1);

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertFalse(valid);
    }

    /// @notice Test with empty tokenOut array when TOKEN_OUT is enabled
    function test_validateTarget_withTokenOut_emptyTokenArray() external {
        // Arrange - TOKEN_OUT enabled with whitelist
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1);
        data = _buildTargetDataWithEmptyTokenOut(recipient, targetChainId, fillExpiry);

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert - should pass (no tokens to validate against whitelist)
        assertTrue(valid);
        assertEq(newOffset, data.length);
    }

    /// @notice Test reads pre-computed tokenOutHash when TOKEN_OUT not enabled
    function test_validateTarget_withoutTokenOut_readsPrecomputedHash() external {
        // Arrange - no TOKEN_OUT validation
        config = _buildConfig(FIELD_RECIPIENT, MODE_SKIP); // Some other field, TOKEN_OUT is
        // SKIP
        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertTrue(valid);

        bytes32 expectedHash = _computeExpectedTargetHash(
            recipient, precomputedTokenOutHash, targetChainId, fillExpiry
        );
        assertEq(targetHash, expectedHash);
    }

    /*//////////////////////////////////////////////////////////////
                       MULTIPLE FIELDS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test all target fields enabled and passing
    function test_validateTarget_withMultipleFields_allPass() external {
        // Arrange - RECIPIENT, FILL_EXPIRY, TOKEN_OUT all enabled
        uint8[] memory fieldIds = new uint8[](3);
        fieldIds[0] = FIELD_RECIPIENT;
        fieldIds[1] = FIELD_FILL_EXPIRY;
        fieldIds[2] = FIELD_TOKEN_OUT;

        uint8[] memory modes = new uint8[](3);
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;
        modes[2] = MODE_CHECK_STORAGE;

        config = _buildConfigMulti(fieldIds, modes);

        _setupRecipient(targetChainId, recipient);
        _setupFillExpiry(targetChainId, 500, 1500);
        _setupTokenOut(targetChainId, token1);

        data = _buildTargetDataWithTokenOut(recipient, targetChainId, fillExpiry, token1, amount1);

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertTrue(valid);
        assertEq(returnedTargetChainId, targetChainId);
    }

    /// @notice Test multiple fields where one fails
    function test_validateTarget_withMultipleFields_oneFails() external {
        // Arrange - RECIPIENT passes, FILL_EXPIRY fails
        uint8[] memory fieldIds = new uint8[](2);
        fieldIds[0] = FIELD_RECIPIENT;
        fieldIds[1] = FIELD_FILL_EXPIRY;

        uint8[] memory modes = new uint8[](2);
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;

        config = _buildConfigMulti(fieldIds, modes);

        _setupRecipient(targetChainId, recipient);
        _setupFillExpiry(targetChainId, 2000, 3000); // fillExpiry=1000 out of bounds

        data = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert
        assertFalse(valid);
    }

    /// @notice Test RECIPIENT_IS_SPONSOR takes precedence over RECIPIENT
    function test_validateTarget_recipientIsSponsorTakesPrecedence() external {
        // Arrange - both RECIPIENT_IS_SPONSOR and RECIPIENT enabled
        uint8[] memory fieldIds = new uint8[](2);
        fieldIds[0] = FIELD_RECIPIENT_IS_SPONSOR;
        fieldIds[1] = FIELD_RECIPIENT;

        uint8[] memory modes = new uint8[](2);
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;

        config = _buildConfigMulti(fieldIds, modes);

        // Set up RECIPIENT storage to expect a DIFFERENT address
        _setupRecipient(targetChainId, address(0xBEEF));

        // But use account as recipient (satisfies RECIPIENT_IS_SPONSOR)
        data = _buildTargetDataWithTokenOutHash(
            account, targetChainId, fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 0, config);

        // Assert - should pass because RECIPIENT_IS_SPONSOR is checked first and passes
        assertTrue(valid);
    }

    /*//////////////////////////////////////////////////////////////
                         OFFSET TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with non-zero offset
    function test_validateTarget_nonZeroOffset() external {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT, MODE_SKIP);
        bytes memory targetData = _buildTargetDataWithTokenOutHash(
            recipient, targetChainId, fillExpiry, precomputedTokenOutHash
        );
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), targetData); // Prepend garbage

        // Act - start at offset 32
        (valid, targetHash, returnedTargetChainId, newOffset) =
            this.validateTargetExternal(data, 32, config);

        // Assert
        assertTrue(valid);
        assertEq(returnedTargetChainId, targetChainId);
        assertEq(newOffset, 32 + targetData.length);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for RECIPIENT_IS_SPONSOR check
    function testFuzz_validateTarget_recipientIsSponsor(
        address _recipient,
        uint256 _targetChainId,
        uint256 _fillExpiry
    )
        external
    {
        // Arrange
        config = _buildConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        data = _buildTargetDataWithTokenOutHash(
            _recipient, _targetChainId, _fillExpiry, precomputedTokenOutHash
        );

        // Act
        (valid,,,) = this.validateTargetExternal(data, 0, config);

        // Assert - valid only if recipient == account
        assertEq(valid, _recipient == account);
    }
}
