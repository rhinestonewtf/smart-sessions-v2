// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Types
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";
import { Execution as ExecutionCompactUtils } from "@compact-utils/common/SmartExecutionLib.sol";

/// @dev Library for parsing different execution types to bypass solidity limitations.
library ExecutionLibV2 {
    /*//////////////////////////////////////////////////////////////
                                 PARSE
    //////////////////////////////////////////////////////////////*/

    /// @notice This is essentially a type-cast between two identical structs
    function parse(ExecutionCompactUtils[] calldata in_)
        internal
        pure
        returns (Execution[] calldata out)
    {
        assembly {
            out.offset := in_.offset
            out.length := in_.length
        }
    }
}
