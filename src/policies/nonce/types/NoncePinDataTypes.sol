// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/*//////////////////////////////////////////////////////////////
                        PERMIT2 CLAIM HEADER
//////////////////////////////////////////////////////////////

The nonce this policy pins lives in the Permit2 claim payload header:

┌───────────┬──────────────────────────────────────────────────┐
│  [0:20]   │  arbiter (Permit2 spender)                       │
│  [20:52]  │  nonce                            ← pinned here  │
│  [52:84]  │  deadline                                        │
│  [84:...] │  tokenIn / mandate                               │
└───────────┴──────────────────────────────────────────────────┘

Mirrors `Permit2ClaimPolicy._decodePermit2Header`, which states the same
offsets inline. The two are not linked: if that layout changes, a policy
reading these keeps reading a stale window and answers wrongly rather than
reverting. Update both together.

//////////////////////////////////////////////////////////////*/

/// @dev Start of the nonce in the Permit2 claim payload, after the arbiter
uint256 constant NONCE_START = 20;

/// @dev End of the nonce in the Permit2 claim payload
uint256 constant NONCE_END = 52;

/*//////////////////////////////////////////////////////////////
                            PINNED NONCE
//////////////////////////////////////////////////////////////*/

/// @notice The nonce pinned for a configuration
/// @dev `configured` is tracked separately so a pinned nonce of zero stays distinguishable
///      from an entry nobody ever wrote
/// @param configured Whether a nonce has been pinned
/// @param nonce The pinned nonce
struct PinnedNonce {
    bool configured;
    uint256 nonce;
}
