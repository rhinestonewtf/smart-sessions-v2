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
import { Constants } from "@compact-utils/types/Constants.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

/// @title BaseValidationLib.validateMandate Unit Tests
/// @notice Unit tests for the validateMandate function
contract BaseValidationLib_validateMandate_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;
    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Results from validateMandate
    bool internal valid;
    bytes32 internal mandateHash;

    /// @notice Mock sub-policy
    MockSubPolicy internal mockSubPolicy;

    /// @notice Test mandate values
    uint128 internal minGas;
    uint256 internal fillExpiry;
    uint256 internal amount1;

    /// @notice Pre-computed hashes for tests
    bytes32 internal precomputedMandateHash;
    bytes32 internal precomputedTargetHash;
    bytes32 internal precomputedTokenOutHash;
    bytes32 internal precomputedOriginOpsHash;
    bytes32 internal precomputedDestOpsHash;
    bytes32 internal precomputedQualificationHash;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();

        minGas = 100_000;
        fillExpiry = 1000;
        amount1 = 1 ether;

        precomputedMandateHash = keccak256("mandateHash");
        precomputedTargetHash = keccak256("targetHash");
        precomputedTokenOutHash = keccak256("tokenOutHash");
        precomputedOriginOpsHash = keccak256("originOpsHash");
        precomputedDestOpsHash = keccak256("destOpsHash");
        precomputedQualificationHash = keccak256("qualificationHash");
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateMandateExternal(
        bytes calldata _data,
        uint256 _offset,
        uint256 _chainId,
        address _arbiter,
        PolicyConfig _config
    )
        external
        view
        returns (bool, bytes32)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return BaseValidationLib.validateMandate(
            $, _data, _offset, _chainId, _arbiter, _config, configId, account, testHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds mandate calldata with all pre-computed hashes (no validation)
    /// @dev Format: [mandateHash: 32]
    function _buildPrecomputedMandateData(bytes32 _mandateHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(_mandateHash);
    }

    /// @notice Builds mandate calldata with pre-computed target but inline ops/qualification
    /// @dev Format: [targetHash: 32][targetChainId: 32][minGas: 16][originOpsHash: 32][destOpsHash:
    /// 32][qualificationHash: 32]
    function _buildMandateDataNoTargetCheck(
        bytes32 _targetHash,
        uint256 _targetChainId,
        uint128 _minGas,
        bytes32 _originOpsHash,
        bytes32 _destOpsHash,
        bytes32 _qualificationHash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            _targetHash, _targetChainId, _minGas, _originOpsHash, _destOpsHash, _qualificationHash
        );
    }

    /// @notice Builds mandate calldata with inline target and pre-computed ops/qualification
    /// @dev Format: [recipient: 20][targetChainId: 32][fillExpiry: 32][tokenOutHash: 32][minGas:
    /// 16][originOpsHash: 32][destOpsHash: 32][qualificationHash: 32]
    function _buildMandateDataWithTargetCheck(
        address _recipient,
        uint256 _targetChainId,
        uint256 _fillExpiry,
        bytes32 _tokenOutHash,
        uint128 _minGas,
        bytes32 _originOpsHash,
        bytes32 _destOpsHash,
        bytes32 _qualificationHash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes20(_recipient),
            _targetChainId,
            _fillExpiry,
            _tokenOutHash,
            _minGas,
            _originOpsHash,
            _destOpsHash,
            _qualificationHash
        );
    }

    /// @notice Builds mandate calldata with inline target and tokenOut array
    function _buildMandateDataWithTokenOut(
        address _recipient,
        uint256 _targetChainId,
        uint256 _fillExpiry,
        address _token,
        uint256 _amount,
        uint128 _minGas,
        bytes32 _originOpsHash,
        bytes32 _destOpsHash,
        bytes32 _qualificationHash
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
            uint256(uint160(_token)),
            _amount,
            _minGas,
            _originOpsHash,
            _destOpsHash,
            _qualificationHash
        );
    }

    /// @notice Computes expected mandate hash
    function _computeExpectedMandateHash(
        bytes32 _targetHash,
        uint128 _minGas,
        bytes32 _originOpsHash,
        bytes32 _destOpsHash,
        bytes32 _qualificationHash
    )
        internal
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashMandateRaw(
            _targetHash, _minGas, _originOpsHash, _destOpsHash, _qualificationHash
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
                      NO MANDATE CHECKS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test reads pre-computed mandateHash when no checks enabled
    function test_validateMandate_noChecksEnabled_readsPrecomputedHash() external {
        // Arrange - no mandate checks enabled (all SKIP)
        config = PolicyConfig.wrap(0);
        data = _buildPrecomputedMandateData(precomputedMandateHash);

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(mandateHash, precomputedMandateHash);
    }

    /*//////////////////////////////////////////////////////////////
                         TARGET CHECK TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test validates target when target check enabled
    function test_validateMandate_withTargetCheck_targetPasses() external {
        // Arrange - RECIPIENT enabled (a target check)
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);

        data = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertNotEq(mandateHash, bytes32(0));
    }

    /// @notice Test returns false when target validation fails
    function test_validateMandate_withTargetCheck_targetFails() external {
        // Arrange - RECIPIENT enabled but wrong recipient
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, address(0xBEEF)); // Different recipient

        data = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertFalse(valid);
        assertEq(mandateHash, bytes32(0));
    }

    /// @notice Test reads pre-computed targetHash when no target checks
    function test_validateMandate_noTargetCheck_readsPrecomputedTargetHash() external {
        // Arrange - only ORIGIN_OPS enabled (not a target check)
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, true); // require ops

        data = _buildMandateDataNoTargetCheck(
            precomputedTargetHash,
            targetChainId,
            minGas,
            precomputedOriginOpsHash, // ops present
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
    }

    /*//////////////////////////////////////////////////////////////
                        ORIGIN_OPS CHECK TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test validates originOps when enabled
    function test_validateMandate_withOriginOpsCheck_originOpsPasses() external {
        // Arrange - ORIGIN_OPS enabled, requires ops
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, true);

        data = _buildMandateDataNoTargetCheck(
            precomputedTargetHash,
            targetChainId,
            minGas,
            precomputedOriginOpsHash, // ops present (not NO_OPS)
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test returns false when originOps validation fails
    function test_validateMandate_withOriginOpsCheck_originOpsFails() external {
        // Arrange - ORIGIN_OPS enabled, requires ops, but NO_OPS provided
        config = _buildConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        _setupOriginOps(chainId, true);

        data = _buildMandateDataNoTargetCheck(
            precomputedTargetHash,
            targetChainId,
            minGas,
            Constants.NO_OPS, // NO ops (fails validation)
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                         DEST_OPS CHECK TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test validates destOps when enabled
    function test_validateMandate_withDestOpsCheck_destOpsPasses() external {
        // Arrange - DEST_OPS enabled, requires ops
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, true);

        // Need to include targetChainId in calldata for destOps to use
        data = _buildMandateDataNoTargetCheck(
            precomputedTargetHash,
            targetChainId,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash, // ops present (not NO_OPS)
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test returns false when destOps validation fails
    function test_validateMandate_withDestOpsCheck_destOpsFails() external {
        // Arrange - DEST_OPS enabled, requires ops, but NO_OPS provided
        config = _buildConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        _setupDestOps(targetChainId, true);

        data = _buildMandateDataNoTargetCheck(
            precomputedTargetHash,
            targetChainId,
            minGas,
            precomputedOriginOpsHash,
            Constants.NO_OPS, // NO ops (fails validation)
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                      QUALIFICATION CHECK TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test validates qualification when enabled (no rules = passes)
    function test_validateMandate_withQualificationCheck_qualificationPasses() external {
        // Arrange - QUALIFICATION enabled with no rules
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        _setupEmptyQualificationRules(chainId, arbiter, false);

        bytes memory qualData = hex"deadbeef";
        data = abi.encodePacked(
            precomputedTargetHash,
            targetChainId,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            uint256(qualData.length),
            qualData
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test qualification validation fails when rules fail
    function test_validateMandate_withQualificationCheck_qualificationFails() external {
        // Arrange - QUALIFICATION enabled with rules that will fail
        config = _buildConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        _setupEqualRule(chainId, arbiter, false, bytes32(uint256(42))); // Expects 42

        bytes memory qualData = abi.encodePacked(bytes32(uint256(99))); // Provides 99 (won't match)
        data = abi.encodePacked(
            precomputedTargetHash,
            targetChainId,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            uint256(qualData.length),
            qualData
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertFalse(valid);
        assertEq(mandateHash, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       MULTIPLE FIELDS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test all mandate fields enabled and passing
    function test_validateMandate_allFieldsEnabled_allPass() external {
        // Arrange - multiple fields enabled
        uint8[] memory fieldIds = new uint8[](3);
        fieldIds[0] = FIELD_RECIPIENT;
        fieldIds[1] = FIELD_ORIGIN_OPS;
        fieldIds[2] = FIELD_DEST_OPS;

        uint8[] memory modes = new uint8[](3);
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;
        modes[2] = MODE_CHECK_STORAGE;

        config = _buildConfigMulti(fieldIds, modes);

        _setupRecipient(targetChainId, recipient);
        _setupOriginOps(chainId, true);
        _setupDestOps(targetChainId, true);

        data = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertNotEq(mandateHash, bytes32(0));
    }

    /// @notice Test early exit when first field fails
    function test_validateMandate_multipleFields_earlyExitOnFailure() external {
        // Arrange - RECIPIENT fails, other fields should not be checked
        uint8[] memory fieldIds = new uint8[](2);
        fieldIds[0] = FIELD_RECIPIENT;
        fieldIds[1] = FIELD_ORIGIN_OPS;

        uint8[] memory modes = new uint8[](2);
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;

        config = _buildConfigMulti(fieldIds, modes);

        _setupRecipient(targetChainId, address(0xBEEF)); // Wrong recipient
        // Don't set up originOps - if it was checked it would also fail

        data = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert - should fail on recipient, not reach originOps
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                           HASH COMPUTATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test correct mandateHash computation when validation is performed
    function test_validateMandate_computesCorrectHash() external {
        // Arrange - enable RECIPIENT check to trigger hash computation
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);

        data = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (valid, mandateHash) = this.validateMandateExternal(data, 0, chainId, arbiter, config);

        // Assert
        assertTrue(valid);

        // Compute expected target hash
        bytes32 expectedTargetHash = _computeExpectedTargetHash(
            recipient, precomputedTokenOutHash, targetChainId, fillExpiry
        );

        // Compute expected mandate hash
        bytes32 expectedMandateHash = _computeExpectedMandateHash(
            expectedTargetHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        assertEq(mandateHash, expectedMandateHash);
    }

    /// @notice Test minGas is included in hash computation
    function test_validateMandate_minGasIncludedInHash() external {
        // Arrange - enable RECIPIENT check to trigger hash computation
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);

        // Build data with minGas = 100_000
        uint128 minGas1 = 100_000;
        bytes memory data1 = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas1,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Build data with minGas = 200_000
        uint128 minGas2 = 200_000;
        bytes memory data2 = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas2,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );

        // Act
        (, bytes32 hash1) = this.validateMandateExternal(data1, 0, chainId, arbiter, config);
        (, bytes32 hash2) = this.validateMandateExternal(data2, 0, chainId, arbiter, config);

        // Assert - different minGas should produce different hashes
        assertNotEq(hash1, hash2);

        // Compute expected target hash (same for both)
        bytes32 expectedTargetHash = _computeExpectedTargetHash(
            recipient, precomputedTokenOutHash, targetChainId, fillExpiry
        );

        // Verify correct computation
        bytes32 expectedHash1 = _computeExpectedMandateHash(
            expectedTargetHash,
            minGas1,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );
        bytes32 expectedHash2 = _computeExpectedMandateHash(
            expectedTargetHash,
            minGas2,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );
        assertEq(hash1, expectedHash1);
        assertEq(hash2, expectedHash2);
    }

    /*//////////////////////////////////////////////////////////////
                            OFFSET TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test with non-zero offset (no checks - reads precomputed hash)
    function test_validateMandate_nonZeroOffset_noChecks() external {
        // Arrange - no validation, just verify offset handling
        config = PolicyConfig.wrap(0);

        bytes memory mandateData = _buildPrecomputedMandateData(precomputedMandateHash);
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), mandateData); // Prepend garbage

        // Act - start at offset 32
        (valid, mandateHash) = this.validateMandateExternal(data, 32, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertEq(mandateHash, precomputedMandateHash);
    }

    /// @notice Test with non-zero offset (with checks)
    function test_validateMandate_nonZeroOffset_withChecks() external {
        // Arrange - RECIPIENT enabled to trigger validation
        config = _buildConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        _setupRecipient(targetChainId, recipient);

        bytes memory mandateData = _buildMandateDataWithTargetCheck(
            recipient,
            targetChainId,
            fillExpiry,
            precomputedTokenOutHash,
            minGas,
            precomputedOriginOpsHash,
            precomputedDestOpsHash,
            precomputedQualificationHash
        );
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), mandateData); // Prepend garbage

        // Act - start at offset 32
        (valid, mandateHash) = this.validateMandateExternal(data, 32, chainId, arbiter, config);

        // Assert
        assertTrue(valid);
        assertNotEq(mandateHash, bytes32(0));
    }
}
