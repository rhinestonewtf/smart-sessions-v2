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
        // (allocator can be address(0) for no allocator)
        if (!isInit && allocator != address(0)) {
            require(
                allocator.isValidERC1271SignatureNowCalldata(hash, allocatorSignature),
                InvalidAllocatorSignature()
            );
        }
    }
}
