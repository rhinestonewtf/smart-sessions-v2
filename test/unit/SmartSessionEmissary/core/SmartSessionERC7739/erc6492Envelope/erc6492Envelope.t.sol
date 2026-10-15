// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";

// Libraries
import { Solarray } from "solarray/Solarray.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @notice ERC-7739 envelopes signed by a real session key, wrapped in ERC-6492
contract SmartSessionERC7739_erc6492Envelope_Test is SmartSessionERC7739_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    string constant PERMIT_TYPE =
        "Permit(address spender,uint256 value,uint256 nonce,uint256 deadline)";

    bytes32 constant ERC6492_MAGIC =
        0x6492649264926492649264926492649264926492649264926492649264926492;

    /// @dev Mode byte, permission id, policy data offset and a 65-byte session key signature
    uint256 constant HEADER_LENGTH = 1 + 32 + 32 + 65;

    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes internal encodeData;
    bytes32 internal hash;
    bytes internal envelope;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        encodeData = abi.encode(address(0xBEEF), 1 ether, uint256(0), uint256(1_700_000_000));
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        hash = _appHash(appDomainSeparator, contents);
        envelope = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    _typedDataSignTypehash("Permit", PERMIT_TYPE),
                    contents
                )
            ),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_erc6492Envelope_ReturnsMagic() public {
        // Arrange
        bytes memory signature = _wrap(makeAddr("factory"), hex"c0ffee", envelope);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a wrapped envelope");
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_erc6492Envelope_AnyFactoryData_ReturnsMagic(
        address factory,
        bytes calldata factoryData
    )
        public
    {
        // Arrange
        bytes memory signature = _wrap(factory, factoryData, envelope);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a wrapped envelope");
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_erc6492Envelope_revertsWhen_InnerByteFlipped(
        bytes calldata factoryData,
        uint256 position,
        uint8 mask
    )
        public
    {
        // Arrange - one byte of the permission id or of the ERC-7739 tail flipped. The policy
        // data offset and the session key signature are left alone: the header trusts the
        // offset, and the ownable validator reverts on a signature it cannot recover.
        mask = uint8(bound(mask, 1, type(uint8).max));
        position = bound(position, 0, 32 + envelope.length - HEADER_LENGTH - 1);
        position = position < 32 ? position + 1 : position - 32 + HEADER_LENGTH;
        bytes memory inner = bytes.concat(envelope);
        inner[position] ^= bytes1(mask);
        bytes memory signature = _wrap(makeAddr("factory"), factoryData, inner);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a flipped byte in the envelope");
    }

    function test_erc6492Envelope_revertsWhen_InnerSignedForOtherStruct() public {
        // Arrange - the wrapper carries an envelope whose session key signature is for 2 ether
        bytes memory otherEncodeData =
            abi.encode(address(0xBEEF), 2 ether, uint256(0), uint256(1_700_000_000));
        bytes memory inner = bytes.concat(envelope);
        for (uint256 i; i < 32; i++) {
            inner[HEADER_LENGTH + 32 + 32 + i] = otherEncodeData[32 + i];
        }
        bytes memory signature = _wrap(makeAddr("factory"), hex"c0ffee", inner);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, otherEncodeData)), signature
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a struct the session key did not sign");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice `abi.encode(factory, factoryData, signature) ‖ magic`, as ERC-6492 defines it
    function _wrap(
        address factory,
        bytes memory factoryData,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(abi.encode(factory, factoryData, signature), ERC6492_MAGIC);
    }
}
