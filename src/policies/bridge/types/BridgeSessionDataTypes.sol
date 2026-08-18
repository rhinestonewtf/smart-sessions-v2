// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/*//////////////////////////////////////////////////////////////
                          SETTLEMENT LAYERS
//////////////////////////////////////////////////////////////

A bridge session authorizes several settlement layers and permits exactly one
settlement across all of them. Each layer records its spend somewhere else, so
the session has to know which layer it is looking at: the nonce sits at a
different offset in each layer's payload, and each layer must be excluded from
its own check.

That exclusion is not a special case, it is the ordering: the layers wired here
consume their nonce BEFORE validating a signature, so a layer that checked the
consumable it is about to burn would reject the settlement it is validating.
The exemption covers exactly that one consumable - not every consumable the
same settlement contract happens to own.

  Permit2 claim payload                 SingleChainOps payload
  ┌───────────┬───────────────┐         ┌───────────┬───────────────┐
  │  [0:20]   │  arbiter      │         │  [0]      │  variant      │
  │  [20:52]  │  nonce    ←   │         │  [1]      │  hasGasRefund │
  │  [52:84]  │  deadline     │         │  [2:22]   │  account      │
  └───────────┴───────────────┘         │  [22:54]  │  nonce    ←   │
                                        └───────────┴───────────────┘

Mirrors `Permit2ClaimPolicy._decodePermit2Header` and
`BaseIntentExecutorPolicy._validateClaim`, each of which states its own offsets
inline. The three are not linked: if either layout changes, a policy reading
these keeps reading a stale window and answers wrongly rather than reverting.

They are anchored differently, and only one of them in `realExecutorLayer`.

22 is anchored there: `test_realExecutorSettlement_validates` drives the real
`BaseIntentExecutorPolicy._validateClaim`, which reads data[22:54], so shifting
either side breaks that test.

20 is NOT anchored by that suite. `test_permit2NonceOffsetMatchesTheRealHeaderLayout`
builds its own header and never touches `Permit2ClaimPolicy` - swapping that
decoder's nonce and deadline windows leaves it green. What does hold 20 is
`BridgeSessionEndToEnd.test_realPermit2SettlementThroughTheMultiplexer`, where a
wrong offset makes a real settlement fail, plus `Permit2ClaimPolicy`'s own suite.
20 does read a digest-bound field: `_decodePermit2Header` folds that nonce into
the digest it compares against `hash`.

The executor payload's leading byte is a `variant`: a second variant carrying
an extra field ahead of the nonce would move this offset, and only the
`realExecutorLayer` assertion would catch it.

//////////////////////////////////////////////////////////////*/

/// @dev Settles through Permit2, which records the spend in its own nonce bitmap. Across and Eco
///      are both this layer - they are different arbiters sharing one consumable, so the choice
///      between them is an arbiter allowlist inside the layer, not a layer of its own
uint8 constant LAYER_PERMIT2 = 0;

/// @dev Settles through the intent executor, which records the spend in its standalone namespace
uint8 constant LAYER_INTENT_EXECUTOR = 1;

/// @dev Number of known layers; any tag at or above this is refused
uint8 constant LAYER_COUNT = 2;

/// @dev Start of the nonce in a Permit2 claim payload, after the arbiter
uint256 constant PERMIT2_NONCE_START = 20;

/// @dev Start of the nonce in a SingleChainOps payload, after variant, flag and account
uint256 constant INTENT_EXECUTOR_NONCE_START = 22;

/// @dev Width of the nonce in every supported payload
uint256 constant NONCE_LENGTH = 32;

/// @dev Width of the layer tag the policy prepends to the payload
uint256 constant LAYER_TAG_LENGTH = 1;

/*//////////////////////////////////////////////////////////////
                            BRIDGE SESSION
//////////////////////////////////////////////////////////////*/

/// @notice One bridge session: one pinned nonce, one settlement policy per permitted layer
/// @dev `configured` is tracked separately so a pinned nonce of zero stays distinguishable from an
///      entry nobody ever wrote
/// @dev `generation` exists because a session can be re-enabled with a NARROWER set of layers and
///      land on the same slot: permissionId is derived from the session validator, its init data
///      and the salt, and covers no policy content at all, so a re-enable that drops a layer
///      reuses this configId. `layerPolicy` is a mapping and cannot be enumerated to clear, so
///      every entry is keyed by generation instead and a bump orphans the whole previous set
/// @param configured Whether this session has been set up
/// @param generation Bumped on every initialization, so stale layers become unreachable
/// @param nonce The nonce every permitted layer competes for
/// @param layerPolicy The settlement policy per (generation, layer), zero where not permitted
struct BridgeSession {
    bool configured;
    uint256 generation;
    uint256 nonce;
    mapping(uint256 generationAndLayer => address policy) layerPolicy;
}
