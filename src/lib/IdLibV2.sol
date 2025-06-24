// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";

// Types
import { PermissionId, ActionId, ConfigId, Erc1271PolicyId } from "@smartsessions/DataTypes.sol";

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
}
