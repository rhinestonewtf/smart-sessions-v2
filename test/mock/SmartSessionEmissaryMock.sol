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
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Constructor to initialize the Smart Session Emissary Mock
    /// @param intentExecutor The address of the Intent Executor contract
    constructor(address intentExecutor) SmartSessionEmissary(intentExecutor) { }

    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable multiple sessions with their associated policies
    function enableSessions(
        Session[] calldata sessions,
        bytes12 lockTag
    )
        external
        returns (PermissionId[] memory permissionIds)
    {
        return _enableSessions(sessions, msg.sender, lockTag);
    }

    /*//////////////////////////////////////////////////////////////
                        TEST HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        CACHE HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

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
