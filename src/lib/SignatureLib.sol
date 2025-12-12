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

    // In SignatureLib:

    /// @notice Validates the allocator and user signatures for a given hash,
    ///         reverts if the signatures are invalid.
    /// @dev Signature requirements:
    ///      - User signature: Always required (unless msg.sender == user)
    ///      - Allocator signature: Required only when isInit=true AND allocator != address(0)
    /// @param hash The hash to validate signatures against
    /// @param allocator The address of the allocator (address(0) if none)
    /// @param user The address of the user
    /// @param allocatorSignature The signature of the allocator
    /// @param userSignature The signature of the user
    /// @param isInit True if lockTag already enabled (require allocator sig), false if first enable
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

        // Verify allocator signature on subsequent enables (isInit=true)
        // Skip if no allocator is configured (allocator == address(0))
        if (isInit && allocator != address(0)) {
            require(
                allocator.isValidERC1271SignatureNowCalldata(hash, allocatorSignature),
                InvalidAllocatorSignature()
            );
        }
    }
}
