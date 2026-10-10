# Settlement-Layer IntentExecutor Policies

Smart-session ERC-1271 policies that gate signatures requested by Rhinestone's
`StandaloneIntentExecutor`. The signer's smart account authorises an
`executeSinglechainOps` (and, in a follow-up, `executeMultichainOps`) intent by
returning the ERC-1271 magic value for the executor's EIP-712 digest. These
policies sit on the 1271 path *inside* Smart Sessions and decide whether to
accept the digest based on:

1. Recomputed EIP-712 digest vs. the configured `IntentExecutor` address.
2. Optional `GasRefund` whitelist (token + exchangeRate cap).
3. Settlement-layer ACL on every inner `(to, value, data)` call.

## Layout

```
shared/                        // typehashes, libs, adapter interface
  BaseIntentExecutorPolicy      abstract: digest + GasRefund + variant gating
  adapters/                    pure validators with typed errors
    RelayAdapter / CCTPAdapter / RhinoAdapter
  interfaces/                  IBaseIntentExecutorPolicy / IIntentExecutorAdapter
  lib/                         EIP-712, ops calldata, per-layer selector libs
  types/                       data-blob constants

intentExecutorStatic/
  StaticIntentExecutorPolicy    fixed-bytecode policy hard-wired to one adapter

intentExecutorOwnable/
  IntentExecutorPolicy          ownable, registry-managed, multi-layer dispatch
```

## Two variants

| | `StaticIntentExecutorPolicy` | `IntentExecutorPolicy` (Ownable) |
| - | - | - |
| Layers per install | **1** (immutable) | N (frozen at install) |
| Adapter address | Immutable constructor arg | Owner-managed mapping (registry) |
| Upgrade | Deploy new policy | Owner registers new adapter (only affects new installs) |
| Trust | Bytecode is the contract | Trust the owner not to swap to a malicious adapter |
| Audit surface | Tiny | Larger (registry + dispatch + adapters) |

The Ownable variant freezes `(layerId, adapter, configHash)` into `LayerStamp`s
at install time, so an owner adapter swap only affects future installs — already
installed sessions keep the adapter they agreed to.

## ⚠ Critical install constraint: one policy per permissionId

Smart Sessions' `erc1271Policy[]` is an **AND**: every enabled 1271 policy for
the matching session must accept. Per-adapter ACLs are mutually exclusive on
target addresses (e.g. a call to Relay's router will `TARGET_DENY` from the
CCTP and Rhino adapters). Stacking multiple of these policies under the same
session permissionId is therefore a misuse:

```text
session A.erc1271Policy[] = [
    StaticPolicy(Relay),
    StaticPolicy(CCTP),     ← misuse: AND-semantics → signature can never validate
    StaticPolicy(Rhino),
]
```

**Don't do this.** A signed Operation whose inner ops are pure Relay would be
accepted by `StaticPolicy(Relay)` and rejected by the other two — the signature
never gets the 1271 magic value back.

### Use one of these patterns instead

**Pattern A — single session, multi-layer (ownable):**

```text
session A.erc1271Policy[] = [
    IntentExecutorPolicy           // one entry; internally routes Relay/CCTP/Rhino
]
```

The user opts into the desired layers at install time. The signer keeps one
session, signs any intent across any opted-in layer.

**Pattern B — one session per layer (static):**

```text
session A (permissionId = pid_relay).erc1271Policy[] = [ StaticPolicy(Relay) ]
session B (permissionId = pid_cctp ).erc1271Policy[] = [ StaticPolicy(CCTP)  ]
session C (permissionId = pid_rhino).erc1271Policy[] = [ StaticPolicy(Rhino) ]
```

The signer/relayer selects which session's permissionId to embed in the
signature based on the intent's settlement layer. Each layer is independently
revocable. **The user is expected to generate a separate permissionId per
layer; the policies must not share one.**

## Where the policy lives in the call stack

```
relayer ──► IntentExecutor.executeSinglechainOps(signedOps)
              │
              └─ ValidateSignature.isValidSignature(...)
                    │
                    ▼  (SigMode = ERC1271 / ERC1271_EMISSARYEXECUTION)
              account.isValidSignature(digest, signature)
                    │
                    ▼  (via SmartSessionCompatibilityFallback)
              SmartSessions.isValidSignatureWithSender(sender, hash, sig)
                    │
                    ▼  for each enabled erc1271Policy in matching session
              (Static|IntentExecutor)Policy.check1271SignedAction(...)
                    │
                    ▼
              digest + GasRefund (base)  →  adapter.validateCall (per inner call)
                    │
                    ▼
              ERC1271_MAGIC_VALUE
```

The Compact `Emissary` contract is a **different** abstraction (stateless
validator for Compact `claim()` signatures) and isn't on this path.

## Adapter dispatch in the Ownable variant

The Ownable policy uses a per-call **layer hint** appended to the data blob:

```
data = base header || ABI(Operation) || callCount(uint8) || hint[0] || ... || hint[N-1]
```

Each `hint` is a `uint8` index into the session's installed `LayerStamp[]`.
The hint is **not** part of the EIP-712 digest — it's an unsigned runtime
annotation supplied by the relayer. Safety: an adapter that doesn't recognise
a call reverts, so a mis-tag costs the relayer a failed TX but cannot bypass
the signer-installed ACLs. The hint index is bounded by `layers.length`, so a
post-install layer added by the owner cannot be smuggled into an existing
session.

## Deployment & install recipe

### Ownable variant — what gets deployed

Three categories of contracts go on-chain:

1. **Adapters** (one per supported settlement layer; stateless, redeployable):
   - `RelayAdapter`
   - `CCTPAdapter`
   - `RhinoAdapter`
2. **`IntentExecutorPolicy`** (single deployment, owned by Rhinestone):
   - Constructor: `new IntentExecutorPolicy(owner)`
   - Holds the `adapterFor[layerId] → address` mapping and the per-`(configId,
     account)` install state.
3. **The smart account + Smart Sessions** are pre-existing infra; the policy
   plugs into the user's existing Smart Sessions install.

### Bootstrap (one-time per chain, by the owner)

```solidity
// 1. Deploy adapters.
RelayAdapter relay = new RelayAdapter();
CCTPAdapter  cctp  = new CCTPAdapter();
RhinoAdapter rhino = new RhinoAdapter();

// 2. Deploy the policy with the operator as owner.
IntentExecutorPolicy policy = new IntentExecutorPolicy(OPERATOR);

// 3. Register adapters under their layerIds. setAdapter() cross-checks the
//    adapter's self-declared layerId() to catch mis-registrations.
vm.startPrank(OPERATOR);
policy.setAdapter(relay.LAYER_ID(), address(relay));
policy.setAdapter(cctp.LAYER_ID(),  address(cctp));
policy.setAdapter(rhino.LAYER_ID(), address(rhino));
vm.stopPrank();
```

To roll out a new settlement layer later: deploy a new adapter implementing
`IIntentExecutorAdapter`, then `policy.setAdapter(NEW_LAYER_ID, address(newAdapter))`.
Existing sessions are unaffected (their `LayerStamp` is frozen) — they'd need
to be re-installed against a new permissionId to opt into the new layer.

### Session install (per user, per session)

The user adds the policy to their Smart Sessions session permission. The
`initData` blob follows the base header layout described in
`BaseIntentExecutorPolicy._validateClaim` plus the ownable-specific tail:

```text
initData =
    intentExecutor (address, 20 bytes)
    flags          (uint8)
    maxExchangeRate(uint256)
    gasTokenCount  (uint8)
    gasTokens      (20 bytes × gasTokenCount)
    // --- ownable extension ---
    layerCount     (uint8)
    repeat × layerCount:
        layerId    (bytes32)
        configLen  (uint16)
        configBytes(configLen bytes)         // adapter-specific blob
```

Then enable the policy under your session's `erc1271Policy[]`:

```solidity
// Pseudocode — exact API depends on your SmartSessions integration.
PolicyData[] memory erc1271Policies = new PolicyData[](1);
erc1271Policies[0] = PolicyData({
    policy: address(policy),
    initData: initData   // the blob built above
});
smartSessions.enableSessions([
    EnableSession({
        permissionId: pid,
        sessionToEnable: Session({
            sessionValidator: ...,
            erc1271Policies: erc1271Policies,
            ...
        })
    })
]);
```

After install:
- `policy.getInstalledLayers(configId, account)` returns the `LayerStamp[]`
  frozen for this session.
- `policy.getLayerConfig(configId, account, layerId)` returns the per-layer
  config blob the session was installed with.

### Static variant — deploy one per layer

```solidity
RelayAdapter relay = new RelayAdapter();
StaticIntentExecutorPolicy relayPolicy =
    new StaticIntentExecutorPolicy(relay);
// install relayPolicy under a Relay-only permissionId
```

Repeat for CCTP / Rhino if the user wants multiple layers — each as its own
permissionId per the install constraint above.

## Known gaps / non-goals (v1)

- `MultiChainOps` validation is scaffolded but disabled (`VariantNotSupported`).
- CCTP / Rhino adversarial tests not yet ported to the new shape — Relay
  serves as the reference suite.
- No on-chain target-address-based dispatch: ERC-20 targets overlap between
  layers (USDC is whitelisted for approve under Relay *and* CCTP), so pure
  target dispatch is ambiguous. See `IntentExecutorPolicy` source for the
  trade-off discussion.
