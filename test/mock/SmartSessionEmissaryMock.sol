// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";

// Types
import {
    PermissionId,
    ActionId,
    ActionData,
    SmartSessionMode,
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
    /// @dev Since this function is only called during the ERC-4337 execution phase, it is safe to
    ///      use the registry
    /// @param sessions An array of Session structures to be enabled
    /// @param lockTag A bytes12 value used to tag the lock
    /// @param arbiter The address of the arbiter for the sessions
    /// @return permissionIds An array of PermissionId values corresponding to the enabled sessions
    function enableSessions(
        Session[] calldata sessions,
        bytes12 lockTag,
        address arbiter
    )
        external
        returns (PermissionId[] memory permissionIds)
    {
        return _enableSessions(sessions, msg.sender, true, lockTag, arbiter);
    }
}
