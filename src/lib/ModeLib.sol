// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

/* //////////////////////////////////////////////////////////////
                            TYPE
//////////////////////////////////////////////////////////////*/

type EmissaryMode is bytes1;

EmissaryMode constant EMISSARY_STATELESS_VALIDATOR = EmissaryMode.wrap(0x00);
EmissaryMode constant EMISSARY_ECDSA = EmissaryMode.wrap(0x01);
EmissaryMode constant EMISSARY_PASSKEY = EmissaryMode.wrap(0x02);
EmissaryMode constant EMISSARY_SMART_SESSION = EmissaryMode.wrap(0x03);

using { eqMode as == } for EmissaryMode global;

/// @notice Checks if the current mode matches the given mode
function eqMode(EmissaryMode self, EmissaryMode mode) pure returns (bool) {
    return EmissaryMode.unwrap(self) == EmissaryMode.unwrap(mode);
}

/// @title Mode Lib
/// @notice Library for managing different verification modes in the Emissary
library ModeLib {
    /// @notice Decodes the verification mode from the given Emissary data
    function decodeMode(bytes calldata emissaryData) internal pure returns (EmissaryMode) {
        return EmissaryMode.wrap(emissaryData[0]);
    }
}
