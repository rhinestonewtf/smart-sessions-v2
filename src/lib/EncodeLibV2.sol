// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @dev Library for unpacking permission ID and data from calldata.
library EncodeLibV2 {
    /*//////////////////////////////////////////////////////////////
                                 UNPACK
    //////////////////////////////////////////////////////////////*/

    function unpack(bytes calldata packed)
        internal
        pure
        returns (PermissionId permissionId, bytes calldata data)
    {
        permissionId = PermissionId.wrap(bytes32(packed[0:32]));
        data = packed[32:];
    }
}
