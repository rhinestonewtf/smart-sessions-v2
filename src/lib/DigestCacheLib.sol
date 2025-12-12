// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @title Digest Cache Library
/// @notice Library for caching digests for account configurations to cache signature verification
/// within a transaction
/// @dev Uses transient storage (TSTORE/TLOAD) to cache verification results that automatically
/// clear after the transaction
library DigestCacheLib {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Constant for representing a verified state in transient storage
    uint256 private constant VERIFIED = 1;

    /// @dev Base slot for transient storage, chosen to avoid collisions
    /// uint256(uint80(bytes10(keccak256(abi.encode(uint256(keccak256("TStoreDigestLib.verification.cache.v1"))
    /// - 1)) & ~bytes32(uint256(0xff))))) >> 176;
    uint256 private constant TSTORE_BASE_SLOT = 0x468e535faa4b0ffe3d06;

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes the transient storage slot for a given digest and session parameters
    /// @dev Hashes the base slot with account, digest, permissionId to create
    ///      a unique slot that avoids collisions across different sessions
    /// @param digest The digest that was verified
    /// @param account The account address associated with the verification
    /// @param permissionId The SmartSession permission identifier
    /// @return slot The computed transient storage slot
    function _computeSlot(
        bytes32 digest,
        address account,
        PermissionId permissionId
    )
        private
        pure
        returns (bytes32 slot)
    {
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)

            // Pack data for hashing: [baseSlot, account, digest, permissionId]
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), permissionId)

            // Compute the unique slot via keccak256
            slot := keccak256(ptr, 0x80)
        }
    }

    /*//////////////////////////////////////////////////////////////
                                  GET
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a digest has already been verified for a SmartSession
    /// @dev Computes a unique slot from the input parameters and checks transient storage
    /// @param digest The digest that was verified
    /// @param account The account address associated with the verification
    /// @param permissionId The SmartSession permission identifier
    /// @return isVerified True if the digest was already verified this transaction
    function isAlreadyVerified(
        bytes32 digest,
        address account,
        PermissionId permissionId
    )
        internal
        view
        returns (bool isVerified)
    {
        bytes32 slot = _computeSlot(digest, account, permissionId);
        assembly {
            isVerified := tload(slot)
        }
    }

    /*//////////////////////////////////////////////////////////////
                                  SET
    //////////////////////////////////////////////////////////////*/

    /// @notice Marks a digest as verified for a SmartSession
    /// @dev Computes a unique slot from the input parameters and stores in transient storage
    /// @param digest The digest that was verified
    /// @param account The account address associated with the verification
    /// @param permissionId The SmartSession permission identifier
    function markAsVerified(bytes32 digest, address account, PermissionId permissionId) internal {
        bytes32 slot = _computeSlot(digest, account, permissionId);
        assembly {
            tstore(slot, VERIFIED)
        }
    }
}
