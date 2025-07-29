// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Libraries
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";

/// @title Signature Library
/// @notice Library for validating allocator and user signatures
library SignatureLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SignatureCheckerLib for address;

    /*//////////////////////////////////////////////////////////////
                                  ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the allocator signature is invalid
    error InvalidAllocatorSignature();

    /// @notice Thrown when the user signature is invalid
    error InvalidUserSignature();

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates the allocator and user signatures for a given hash,
    ///         reverts if the signatures are invalid.
    /// @param hash The hash to validate signatures against
    /// @param allocator The address of the allocator
    /// @param user The address of the user
    /// @param allocatorSignature The signature of the allocator
    /// @param userSignature The signature of the user
    /// @param isInit Whether this is an initialization call
    function verifySignatures(
        bytes32 hash,
        address allocator,
        address user,
        bytes calldata allocatorSignature,
        bytes calldata userSignature,
        bool isInit
    )
        internal
        view
    {
        // Verify user signature if the sender is not the user
        if (msg.sender != user) {
            require(user.isValidSignatureNowCalldata(hash, userSignature), InvalidUserSignature());
        }

        // If this is not an initialization call, verify the allocator signature
        if (!isInit) {
            require(
                allocator.isValidSignatureNowCalldata(hash, allocatorSignature),
                InvalidAllocatorSignature()
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 ECDSA
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates an ECDSA signature for a given hash, only supports 65-byte signatures.
    /// @param hash The hash to validate the signature against
    /// @param signature The ECDSA signature to validate
    /// @return result The address that signed the hash
    function recoverECDSA(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        returns (address result)
    {
        /// @solidity memory-safe-assembly
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let m := mload(0x40) // Cache free memory pointer
            mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // 'v'
            calldatacopy(0x40, signature.offset, 0x40) // Copy 'r' and 's'
            mstore(0x00, hash) // Store the hash
            result := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)) // Call ecrecover
            // `returndatasize() will be '0x20' if successful, otherwise it will be '0'.
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0x00) // Restore the zero slot
            mstore(0x40, m) // Restore free memory pointer
        }
    }
}
