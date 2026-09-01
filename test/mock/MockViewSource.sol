// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

/// @title MockViewSource
/// @notice Mock staticcall target with full control over returndata shape
/// @dev Answers ANY selector through the fallback, so a policy can call whatever view function it
///      was configured with. Exists to prove `StaticcallEqualityPolicy` fails closed against the
///      answers a real callee can give: reverting, returning nothing, returning a short word, or
///      returning more than one word.
///
///      The fallback is not marked `view` because Solidity does not allow it, but it only reads
///      state, so it is reachable through STATICCALL. Configuration must therefore happen in a
///      separate, ordinary transaction before the policy is invoked.
contract MockViewSource {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice First 32 bytes of the returndata
    bytes32 public value;

    /// @notice Total number of bytes to return
    uint256 public returnSize = 32;

    /// @notice Whether the call should revert
    bool public shouldRevert;

    /// @notice Number of bytes of junk to return in a revert
    uint256 public revertSize;

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the word returned to callers
    function setValue(bytes32 newValue) external {
        value = newValue;
    }

    /// @notice Sets how many bytes of returndata the fallback produces
    function setReturnSize(uint256 newSize) external {
        returnSize = newSize;
    }

    /// @notice Makes the fallback revert, with `size` bytes of revert data
    function setRevert(bool enabled, uint256 size) external {
        shouldRevert = enabled;
        revertSize = size;
    }

    /*//////////////////////////////////////////////////////////////
                               FALLBACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns `returnSize` bytes whose first word is `value`, or reverts
    // solhint-disable-next-line no-complex-fallback
    fallback() external {
        bool doRevert = shouldRevert;
        uint256 revSize = revertSize;
        uint256 size = returnSize;
        bytes32 word = value;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Grab a zeroed scratch buffer large enough for whichever payload is produced
            let ptr := mload(0x40)
            let needed := add(size, revSize)
            // Round up to a word and zero it so the tail of an over-long return is deterministic
            let words := div(add(needed, 31), 32)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } { mstore(add(ptr, mul(i, 32)), 0) }

            if doRevert { revert(ptr, revSize) }

            mstore(ptr, word)
            return(ptr, size)
        }
    }
}
