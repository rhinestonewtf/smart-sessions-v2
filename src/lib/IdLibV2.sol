// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLib as CompactIdLib, ResetPeriod, Scope } from "@the-compact/lib/IdLib.sol";

// Types
import { PermissionId, ActionId, ConfigId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

library IdLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;
    using CompactIdLib for *;

    /*//////////////////////////////////////////////////////////////
                                CONVERT
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted toConfigId from IdLib to work with address instead of msg.sender
    function toConfigId(
        PermissionId permissionId,
        ActionId actionId,
        address account
    )
        internal
        pure
        returns (ConfigId _id)
    {
        _id = permissionId.toActionPolicyId(actionId).toConfigId(account);
    }

    /// @dev Adjusted toPermissionId to work with the new Session type
    function toPermissionIdMemory(Session memory session)
        internal
        pure
        returns (PermissionId permissionId)
    {
        permissionId = PermissionId.wrap(
            keccak256(
                abi.encode(session.sessionValidator, session.sessionValidatorInitData, session.salt)
            )
        );
    }

    /// @dev Adjusted toPermissionId to work with the new Session type
    function toPermissionId(Session calldata session)
        internal
        pure
        returns (PermissionId permissionId)
    {
        permissionId = PermissionId.wrap(
            keccak256(
                abi.encode(session.sessionValidator, session.sessionValidatorInitData, session.salt)
            )
        );
    }

    /// @dev Calculates lockTag from allocator, scope, resetPeriod, defaults to NO_LOCKTAG if no
    /// allocator is set
    function deriveLockTag(
        address allocator,
        Scope scope,
        ResetPeriod resetPeriod
    )
        internal
        pure
        returns (bytes12 lockTag)
    {
        // If no allocator is set, use NO_LOCKTAG, otherwise derive from allocator
        if (allocator != address(0)) {
            lockTag = allocator.toAllocatorId().toLockTag(scope, resetPeriod);
        }
        // Defaults to NO_LOCKTAG
    }
}
