// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @title Digest Cache Library
/// @notice Library for caching digests for account configurations to cache signature verification
///         within a transaction
/// @dev Uses transient storage (TSTORE/TLOAD) to cache verification results that automatically
///      clear after the transaction
library DigestCacheLib {
    /*//////////////////////////////////////////////////////////////
                                CONSTANT
    //////////////////////////////////////////////////////////////*/

    /// @dev Constant for representing a verified state in transient storage
    uint256 private constant VERIFIED = 1;

    /// @dev Base slot for transient storage, chosen to avoid collisions
    /// uint256(uint80(bytes10(keccak256(abi.encode(uint256(keccak256("TStoreDigestLib.verification.cache.v1"))
    /// - 1)) & ~bytes32(uint256(0xff))))) >> 176;
    uint256 private constant TSTORE_BASE_SLOT = 0x468e535faa4b0ffe3d06;

    /*//////////////////////////////////////////////////////////////
                             ECDSA/PASSKEY
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if verified for ECDSA/Passkey mode
    function isAlreadyVerified(
        bytes32 digest,
        address account,
        uint8 configId,
        bytes12 lockTag
    )
        internal
        view
        returns (bool isVerified)
    {
        bytes32 slot;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Calculate the storage slot using keccak256 hash
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), configId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            // Load the value from transient storage
            isVerified := tload(slot)
        }
    }

    /// @notice Marks as verified for ECDSA/Passkey mode
    function markAsVerified(
        bytes32 digest,
        address account,
        uint8 configId,
        bytes12 lockTag
    )
        internal
    {
        bytes32 slot;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Calculate the storage slot using keccak256 hash
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), configId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            // Store the VERIFIED constant in transient storage
            tstore(slot, VERIFIED)
        }
    }

    /*//////////////////////////////////////////////////////////////
                           STATELESS VALIDATOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if verified for Stateless Validator mode
    function isAlreadyVerified(
        bytes32 digest,
        address account,
        IStatelessValidator validator,
        uint8 configId,
        bytes12 lockTag
    )
        internal
        view
        returns (bool isVerified)
    {
        bytes32 slot;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Calculate the storage slot using keccak256 hash
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), validator)
            mstore(add(ptr, 0x80), configId)
            mstore(add(ptr, 0xa0), lockTag)
            slot := keccak256(ptr, 0xc0)
            // Load the value from transient storage
            isVerified := tload(slot)
        }
    }

    /// @notice Marks as verified for Stateless Validator mode
    function markAsVerified(
        bytes32 digest,
        address account,
        IStatelessValidator validator,
        uint8 configId,
        bytes12 lockTag
    )
        internal
    {
        bytes32 slot;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Calculate the storage slot using keccak256 hash
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), validator)
            mstore(add(ptr, 0x80), configId)
            mstore(add(ptr, 0xa0), lockTag)
            slot := keccak256(ptr, 0xc0)
            // Store the VERIFIED constant in transient storage
            tstore(slot, VERIFIED)
        }
    }

    /*//////////////////////////////////////////////////////////////
                             SMART SESSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if verified for SmartSession mode
    function isAlreadyVerified(
        bytes32 digest,
        address account,
        PermissionId permissionId,
        bytes12 lockTag
    )
        internal
        view
        returns (bool isVerified)
    {
        bytes32 slot;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Calculate the storage slot using keccak256 hash
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), permissionId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            // Load the value from transient storage
            isVerified := tload(slot)
        }
    }

    /// @notice Marks as verified for SmartSession mode
    function markAsVerified(
        bytes32 digest,
        address account,
        PermissionId permissionId,
        bytes12 lockTag
    )
        internal
    {
        bytes32 slot;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Calculate the storage slot using keccak256 hash
            mstore(ptr, TSTORE_BASE_SLOT)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), permissionId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            // Store the VERIFIED constant in transient storage
            tstore(slot, VERIFIED)
        }
    }
}
