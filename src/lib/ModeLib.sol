// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/*//////////////////////////////////////////////////////////////
                            TYPE
//////////////////////////////////////////////////////////////*/

type EmissaryMode is bytes1;

// Emissary modes (for verifyClaim/verifyExecution)
EmissaryMode constant EMISSARY_VANILLA = EmissaryMode.wrap(0x00);
EmissaryMode constant EMISSARY_SMART_SESSION = EmissaryMode.wrap(0x01);

// ERC-1271 signature modes (for isValidSignatureWithSender)
type SignatureMode is bytes1;

SignatureMode constant IS_VALID_SIG_1271 = SignatureMode.wrap(0x00);
SignatureMode constant IS_VALID_SIG_1271_7739 = SignatureMode.wrap(0x01);

using { eqEmissaryMode as == } for EmissaryMode global;
using { eqSignatureMode as == } for SignatureMode global;

/// @notice Checks if the current emissary mode matches the given mode
function eqEmissaryMode(EmissaryMode self, EmissaryMode mode) pure returns (bool) {
    return EmissaryMode.unwrap(self) == EmissaryMode.unwrap(mode);
}

/// @notice Checks if the current signature mode matches the given mode
function eqSignatureMode(SignatureMode self, SignatureMode mode) pure returns (bool) {
    return SignatureMode.unwrap(self) == SignatureMode.unwrap(mode);
}

/// @title Mode Lib
/// @notice Library for managing different verification modes in the Emissary
library ModeLib {
    /// @notice Decodes the emissary mode from the given Emissary data
    function decodeEmissaryMode(bytes calldata emissaryData) internal pure returns (EmissaryMode) {
        return EmissaryMode.wrap(emissaryData[0]);
    }

    /// @notice Decodes the signature mode from the given signature data
    function decodeSignatureMode(bytes calldata signature) internal pure returns (SignatureMode) {
        return SignatureMode.wrap(signature[0]);
    }
}
