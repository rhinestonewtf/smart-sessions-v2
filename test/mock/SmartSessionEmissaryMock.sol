// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import {
    PermissionId,
    ActionId,
    ActionData,
    SignerConf,
    EnumerableActionPolicy,
    PolicyType,
    EMPTY_PERMISSIONID,
    Policy
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

/// @dev Extended SmartSessionEmissary with helpers for testing purposes.
contract SmartSessionEmissaryMock is SmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable multiple sessions with their associated policies
    function enableSessions(
        Session[] calldata sessions,
        bytes12 lockTag,
        address sender
    )
        external
        returns (PermissionId[] memory permissionIds)
    {
        return _enableSessions(sessions, msg.sender, lockTag, sender);
    }

    /*//////////////////////////////////////////////////////////////
                        TEST HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        CACHE HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if ECDSA digest is cached
    function isDigestCachedECDSA(
        address account,
        bytes32 digest,
        uint8 configId,
        bytes12 lockTag
    )
        external
        view
        returns (bool)
    {
        return DigestCacheLib.isAlreadyVerified(digest, account, configId, lockTag);
    }

    /// @notice Set ECDSA digest cache
    function setDigestCacheECDSA(
        address account,
        bytes32 digest,
        uint8 configId,
        bytes12 lockTag
    )
        external
    {
        DigestCacheLib.markAsVerified(digest, account, configId, lockTag);
    }

    /// @notice Check if Stateless Validator digest is cached
    function isDigestCachedStateless(
        address account,
        bytes32 digest,
        address validator,
        uint8 configId,
        bytes12 lockTag
    )
        external
        view
        returns (bool)
    {
        return DigestCacheLib.isAlreadyVerified(
            digest, account, IStatelessValidator(validator), configId, lockTag
        );
    }

    /// @notice Set Stateless Validator digest cache
    function setDigestCacheStateless(
        address account,
        bytes32 digest,
        address validator,
        uint8 configId,
        bytes12 lockTag
    )
        external
    {
        DigestCacheLib.markAsVerified(
            digest, account, IStatelessValidator(validator), configId, lockTag
        );
    }

    /// @notice Check if SmartSession digest is cached
    function isDigestCachedSmartSession(
        address account,
        bytes32 digest,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
        view
        returns (bool)
    {
        return DigestCacheLib.isAlreadyVerified(digest, account, permissionId, lockTag);
    }

    /// @notice Set SmartSession digest cache
    function setDigestCacheSmartSession(
        address account,
        bytes32 digest,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
    {
        DigestCacheLib.markAsVerified(digest, account, permissionId, lockTag);
    }

    /// @notice Clear ECDSA digest cache
    function clearDigestCacheECDSA(
        address account,
        bytes32 digest,
        uint8 configId,
        bytes12 lockTag
    )
        external
    {
        bytes32 slot;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x468e535faa4b0ffe3d06) // TSTORE_BASE_SLOT
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), configId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            tstore(slot, 0)
        }
    }

    /// @notice Clear Stateless Validator digest cache
    function clearDigestCacheStateless(
        address account,
        bytes32 digest,
        address validator,
        uint8 configId,
        bytes12 lockTag
    )
        external
    {
        bytes32 slot;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x468e535faa4b0ffe3d06)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), validator)
            mstore(add(ptr, 0x80), configId)
            mstore(add(ptr, 0xa0), lockTag)
            slot := keccak256(ptr, 0xc0)
            tstore(slot, 0)
        }
    }

    /// @notice Clear SmartSession digest cache
    function clearDigestCacheSmartSession(
        address account,
        bytes32 digest,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
    {
        bytes32 slot;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x468e535faa4b0ffe3d06)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), permissionId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            tstore(slot, 0)
        }
    }
}
