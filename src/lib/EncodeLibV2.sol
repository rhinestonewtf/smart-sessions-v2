// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { LibZip } from "@solady/utils/LibZip.sol";
import { SmartSessionModeLib } from "@smartsessions/lib/SmartSessionModeLib.sol";

// Types
import { PermissionId, SmartSessionMode } from "@smartsessions/DataTypes.sol";
import { SmartSessionEmissaryEnable, SmartSessionEmissaryConfig } from "@types/DataTypes.sol";

/// @dev Library for unpacking permission ID and data from calldata.
library EncodeLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using LibZip for bytes;
    using SmartSessionModeLib for *;

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the Smart Session Emissary enable data, config, and signature from the
    ///         packed and compressed calldata.
    function decodeEnable(bytes calldata packedSig)
        internal
        pure
        returns (
            SmartSessionEmissaryEnable memory enableData,
            SmartSessionEmissaryConfig memory config,
            bytes memory signature
        )
    {
        (enableData, config, signature) = abi.decode(
            packedSig.flzDecompress(),
            (SmartSessionEmissaryEnable, SmartSessionEmissaryConfig, bytes)
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 UNPACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Unpacks the Smart Session mode, permission ID (if applicable), and data from the
    function unpackMode(bytes calldata packed)
        internal
        pure
        returns (SmartSessionMode mode, PermissionId permissionId, bytes calldata data)
    {
        mode = SmartSessionMode(uint8(bytes1(packed[:1])));
        if (mode.isEnableMode()) {
            data = packed[1:];
        } else {
            permissionId = PermissionId.wrap(bytes32(packed[1:33]));
            data = packed[33:];
        }
    }
}
