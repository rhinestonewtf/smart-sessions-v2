// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";

// Types
import { PermissionId, ActionId, ConfigId, Erc1271PolicyId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

library IdLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;

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
}
