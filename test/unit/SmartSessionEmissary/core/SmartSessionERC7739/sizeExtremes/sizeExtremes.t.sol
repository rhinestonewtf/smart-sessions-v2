// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";

// Libraries
import { LibString } from "solady/utils/LibString.sol";
import { Solarray } from "solarray/Solarray.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @notice The trailer's `uint16` word count and description length at and near their maxima.
///         The session validator accepts any signature, so only the envelope can reject.
contract SmartSessionERC7739_sizeExtremes_Test is SmartSessionERC7739_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MAX = type(uint16).max;

    string constant SMALL_TYPE = "Small(uint256 f)";

    /// @dev The fields after the long contents name in `_longType`
    string constant LONG_TYPE_FIELDS = "(uint256 f)";

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_sizeExtremes_MaxDescriptionLength_ReturnsMagic() public {
        // Arrange
        bytes memory description = _longType(MAX);
        bytes memory encodeData = abi.encode(uint256(1));

        // Act
        (bool reverted, bytes4 result) = _validate(description, encodeData);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a 65535-byte description");
    }

    function test_sizeExtremes_MaxWordCount_ReturnsMagic() public {
        // Arrange
        bytes memory encodeData = new bytes(MAX * 32);
        encodeData[encodeData.length - 1] = 0x01;

        // Act
        (bool reverted, bytes4 result) = _validate(bytes(SMALL_TYPE), encodeData);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept 65535 words of encodeData");
    }

    function test_sizeExtremes_MaxWordCountAndDescriptionLength_ReturnsMagic() public {
        // Arrange
        bytes memory encodeData = new bytes(MAX * 32);
        encodeData[0] = 0x01;

        // Act
        (bool reverted, bytes4 result) = _validate(_longType(MAX), encodeData);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept both at their maxima");
    }

    function test_sizeExtremes_revertsWhen_MaxWordCountAndDescriptionLengthWithBoundHash() public {
        // Arrange - both at their maxima, one encodeData word changed after the hash was bound
        bytes memory description = _longType(MAX);
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = new bytes(MAX * 32);
        bytes32 hash = _appHash(appDomainSeparator, _hashStruct(string(description), encodeData));
        encodeData[MAX * 16] = 0x01;
        bytes memory signature =
            _envelope(permissionId, "", appDomainSeparator, encodeData, description);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a changed word");
    }

    function test_sizeExtremes_revertsWhen_TrailerClaimsMaximaOverShortTail() public {
        // Arrange
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(SMALL_TYPE));
        bytes memory signature = abi.encodePacked(
            bytes1(0x01),
            permissionId,
            uint256(64),
            appDomainSeparator,
            abi.encode(uint256(1)),
            SMALL_TYPE,
            uint16(MAX),
            uint16(MAX)
        );

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            _appHash(appDomainSeparator, _hashStruct(SMALL_TYPE, abi.encode(uint256(1)))), signature
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a trailer longer than the tail");
    }

    function test_sizeExtremes_revertsWhen_MaxLengthDescriptionHasNoParenthesis() public {
        // Arrange - an enabled 65535-byte description with no ')', so the explicit-mode scan
        // runs over all of it
        bytes memory description = bytes(LibString.repeat("A", MAX));
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = abi.encode(uint256(1));
        bytes memory signature =
            _envelope(permissionId, "", appDomainSeparator, encodeData, description);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            _appHash(appDomainSeparator, _hashStruct(string(description), encodeData)), signature
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a hash over the whole description");
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_sizeExtremes_ArbitraryTrailerOverBoundedTail_NeverReverts(
        bytes32 hash,
        uint16 wordCount,
        uint16 descriptionLength,
        bytes calldata tail
    )
        public
    {
        // Arrange - the trailer's counts range over all uint16 values, the tail stays short
        vm.assume(hash != ERC7739_DETECTION_HASH);
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(SMALL_TYPE));
        bytes memory signature = abi.encodePacked(
            bytes1(0x01), permissionId, uint256(64), tail, wordCount, descriptionLength
        );

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertTrue(
            result == ERC1271_MAGIC_VALUE || result == INVALID_SIGNATURE,
            "Should return the magic value or INVALID_SIGNATURE"
        );
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_sizeExtremes_NearMaxDescriptionLength_ReturnsMagic(
        uint256 descriptionLength,
        uint256 wordCount,
        bool explicitMode
    )
        public
    {
        // Arrange
        descriptionLength = bound(descriptionLength, MAX - 1024, MAX);
        wordCount = bound(wordCount, 1, 16);
        // In explicit mode the type is one byte shorter, leaving room for a one-byte name
        bytes memory contentsType =
            _longType(explicitMode ? descriptionLength - 1 : descriptionLength);
        bytes memory description = explicitMode ? abi.encodePacked(contentsType, "B") : contentsType;
        bytes memory encodeData = new bytes(wordCount * 32);
        encodeData[0] = bytes1(uint8(descriptionLength));

        // Act
        (bool reverted, bytes4 result) = _validate(description, contentsType, encodeData);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a near-max description");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables the implicit-mode `contentsType` and validates a correctly bound envelope
    function _validate(
        bytes memory contentsType,
        bytes memory encodeData
    )
        internal
        returns (bool reverted, bytes4 result)
    {
        return _validate(contentsType, contentsType, encodeData);
    }

    /// @notice Enables `description` and validates a correctly bound envelope over `encodeData`
    function _validate(
        bytes memory description,
        bytes memory contentsType,
        bytes memory encodeData
    )
        internal
        returns (bool reverted, bytes4 result)
    {
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(string(description)));
        bytes memory signature =
            _envelope(permissionId, "", appDomainSeparator, encodeData, description);
        return _tryIsValidSignature(
            _appHash(appDomainSeparator, _hashStruct(string(contentsType), encodeData)), signature
        );
    }

    /// @notice `BBB...B(uint256 f)`, `length` bytes long
    function _longType(uint256 length) internal pure returns (bytes memory) {
        return abi.encodePacked(
            LibString.repeat("B", length - bytes(LONG_TYPE_FIELDS).length), LONG_TYPE_FIELDS
        );
    }
}
