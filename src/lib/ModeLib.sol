// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Types
import { VerificationMode } from "@types/DataTypes.sol";

/// @title Mode Lib
/// @notice Library for managing different verification modes in the Emissary
library ModeLib {
    /// @notice Decodes the verification mode from the given Emissary data
    function decodeMode(bytes calldata emissaryData) internal pure returns (VerificationMode) {
        return VerificationMode(uint8(emissaryData[0]));
    }
}
