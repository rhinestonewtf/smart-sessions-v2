# EIP-1271 IntentExecutor Policy

## Goal

Smart-session policies that gate ERC-1271 signatures requested by the
**IntentExecutor** (`compact-utils/src/executor/StandaloneIntent/StandaloneIntent.sol`).
Each policy is bound to a **settlement layer** (Relay, CCTP, Rhino, …) because the
embedded `(to, value, data)` calls differ per layer. This spec covers:

1. **`BaseIntentExecutorPolicy`** — shared EIP-712 digest recomputation,
   account/nonce checks, `GasRefund` validation, and an abstract
   `_validateOps` hook.
2. **`RelayIntentExecutorPolicy`** — first concrete subclass: walks the
   `Operation.ops` calldata and validates Relay-shaped targets/selectors.

Out of scope for v1: CCTP and Rhino policies (same pattern, follow-up).

## Background

`StandaloneIntent.sol` exposes four entrypoints. Each takes a struct that the
account ERC-1271-signs over the EIP-712 domain:

```
name    = "IntentExecutor"
version = "v0.0.1"
```

Structs (from `executor/interfaces/IStandaloneIntent.sol` and
`executor/StandaloneIntent/lib/EIP712Lib.sol`):

```solidity
struct SingleChainOps {
    address account;
    uint256 nonce;
    Operation ops;       // (bytes32 vt, Ops[] ops)
    bytes signature;
}

struct MultiChainOps {
    address account;
    uint256 chainIndex;
    bytes32[] otherChains;
    uint256 nonce;
    Operation ops;
    bytes signature;
}

struct GasRefund { address token; uint256 exchangeRate; }

struct Operation { bytes32 vt; Ops[] ops; }   // Types.Operation
struct Ops { address to; uint256 value; bytes data; }
```

EIP-712 typehashes (verbatim from `EIP712Lib.sol`):

| Struct          | Hash                                                                                    |
|-----------------|-----------------------------------------------------------------------------------------|
| `GasRefund`     | `0xd191c0fb688d2d2f2d6651e977afc984f19d1e4d893b6c824d76841641cf8c69`                   |
| `NO_GASREFUND`  | `0x2a2e93882f19103eba0384726c9f0fc4688a6ecb1e90bef28a42ac83bffe95d8`                   |
| `ChainOps`      | `0xe5f4d4fdb51b63dbc6701734328816a14e98d3a7e8f1d44b257549cba3a2a10d`                   |
| `MultiChainOps` | `0x7f83182523d5e7bd48846ca116dc2ec1c401d2a14f1db70530fb5f5751579395`                   |
| `SingleChainOps`| `0xd6367c390511eb9f5abdcb53b78e1ed925a1e4ba0eb97b7cfd7ae56499b153ea`                   |

V1 supports **only `SingleChainOps`**. Base is structured so `MultiChainOps`
slots in by adding a second `validateMultiChainOps` path that follows
`hashChainOps` → merkle-insert → `MULTICHAINOPS_TYPEHASH`.

## File layout

```
src/policies/intentExecutor/
├── base/
│   ├── BaseIntentExecutorPolicy.sol
│   ├── lib/
│   │   ├── IntentExecutorEIP712Lib.sol
│   │   ├── OpsCalldataLib.sol
│   │   ├── IntentExecutorStorageLib.sol
│   │   └── IntentExecutorConfigLib.sol
│   ├── interfaces/IBaseIntentExecutorPolicy.sol
│   └── types/IntentExecutorDataTypes.sol
└── relay/
    ├── RelayIntentExecutorPolicy.sol
    ├── lib/RelayCalldataLib.sol
    └── interfaces/IRelayIntentExecutorPolicy.sol

test/unit/policies/intentExecutor/
├── BaseIntentExecutorPolicy/
└── RelayIntentExecutorPolicy/
```

`base/` does not inherit `BaseClaimPolicy` — claim machinery (tokenIn, mandate,
arbiter, target chain) doesn't apply here. Reuse smart-session policy plumbing
(`IUserOpPolicy`/`IActionPolicy` interfaces, `ConfigId` storage pattern) but the
state shape is intent-specific.

## Calldata layout passed to `check1271SignedAction`

The smart-session `check1271SignedAction(configId, account, hash, data)` call
receives the EIP-1271 `hash` (digest) plus arbitrary `data`. The relayer that
fills the intent ships:

```
data layout (single-chain, packed):
┌─────────────────────────────────────────────────────────────────────┐
│ [0]        variant (uint8)         0 = SingleChain, 1 = MultiChain  │
│ [1]        hasGasRefund (uint8)    0/1                              │
│ [2:22]     account (address)                                        │
│ [22:54]    nonce (uint256)                                          │
│ [54:74]    gasRefundToken (address)   present iff hasGasRefund      │
│ [74:106]   gasRefundExchangeRate (uint256) present iff hasGasRefund │
│ [...]      Operation { bytes32 vt; Ops[] ops } abi-encoded          │
└─────────────────────────────────────────────────────────────────────┘
```

V1: `variant == 0` only; `variant == 1` reverts `UnsupportedVariant`.

## Base validation flow

```
_validateClaim(configId, account, hash, data):
  (variant, hasGasRefund, account_, nonce, gasRefund, ops) = decode(data)
  require(variant == SINGLE_CHAIN)               // v1 gate
  require(account_ == account)                   // bound to caller
  cfg = $.config(configId, account)
  if (cfg.accountIsFixed) require(account == cfg.account)
  if (cfg.requireGasRefund) require(hasGasRefund)
  if (hasGasRefund) {
      require(cfg.gasTokenWhitelist.contains(gasRefund.token))
      require(gasRefund.exchangeRate <= cfg.maxExchangeRate)
      gasRefundHash = hashGasRefund(gasRefund.token, gasRefund.exchangeRate)
  } else {
      gasRefundHash = NO_GASREFUND
  }
  opsHash = hashOps(ops)                         // matches EIP712TypeHashLib.hashOps
  structHash = hashSingleChainOps(account, nonce, opsHash, gasRefundHash)
  digest = _hashTypedData(structHash, "IntentExecutor", "v0.0.1", IE_address)
  require(digest == hash)
  return _validateOps(configId, $, ops)          // virtual — settlement-layer hook
```

`_validateOps` is `internal virtual returns (bool)` — base defaults to `true`
(no per-call restrictions); subclasses override to whitelist
targets/selectors/args.

### Domain

`IntentExecutor` uses `solady/utils/EIP712`. We **don't** call into the
deployed executor for its domain — we recompute it deterministically from
`(name, version, chainId, verifyingContract)` where `verifyingContract` is the
IntentExecutor address stored in policy config (immutable per-configId).

## Config

```solidity
struct IntentExecutorConfig {
    address intentExecutor;        // verifyingContract for EIP-712
    bool    requireGasRefund;      // hard-require non-NO_GASREFUND
    uint256 maxExchangeRate;       // cap on gasRefund.exchangeRate
    // gas token whitelist held in EnumerableSetLib.AddressSet
    // settlement-layer-specific config appended by subclass init
}
```

Init data layout (initial):

```
[0:20]   intentExecutor
[20]     requireGasRefund (uint8)
[21:53]  maxExchangeRate (uint256)
[53]     gasTokenCount (uint8)
[54:..]  gasTokens (20 bytes each)
[..]     subclass-init blob
```

## Relay subclass

Relay-specific target whitelist + selector dispatch derived from the
orchestrator code paths:

- **Standalone path** (`fillSponsoredIntent` / `fillWithGasRefund`,
  `standaloneDestination = IntentExecutor`): there are *no* on-chain wrapper
  calls — the relayer hits `IntentExecutor.executeSinglechainOps(...)`
  directly. The signed `Operation.ops` is the user's destination ops (e.g.
  approve + multicall on Relay's router, or direct token transfers). Relay
  policy whitelists:
    - Relay `ERC20Router` (`multicall`, `transferAndMulticall`)
    - Configured ERC20 tokens (`approve(address,uint256)` to the router only,
      `transfer(address,uint256)` to the configured recipient only)
    - `IntentExecutorAdapter` (when present)

- **Adapter path** (orchestrator's `handleFill_intentExecutor_*`): the relayer
  calls through `RhinestoneRouter → IntentExecutorAdapter → IntentExecutor`.
  The signed digest still covers the user's destination ops; the wrapper is
  not signed. So nothing extra to validate here — same `_validateOps`.

Subclass config:

```solidity
struct RelayConfig {
    address relayRouter;       // Relay ERC20Router / multicaller
    address intentExecutorAdapter;
    // tokenOut whitelist (EnumerableSetLib.AddressSet)
    // recipient whitelist (EnumerableSetLib.AddressSet) — for token transfer.to
}
```

`_validateOps` walks `Operation.ops` (an `Ops[]`):

| selector / target              | rule                                            |
|--------------------------------|-------------------------------------------------|
| `to == relayRouter`            | `data` selector ∈ {`multicall`, `transferAndMulticall`} |
| `to == intentExecutorAdapter`  | `data` selector ∈ {`handleFill_*`}              |
| `to ∈ tokenOut whitelist`      | `approve(spender, amount)` with `spender == relayRouter`, OR `transfer(to, amount)` with `to ∈ recipient whitelist` |
| anything else                  | revert / return false                           |

`value` rule: `value == 0` unless `to == relayRouter` (allow ETH for swaps).

## Walking `Ops[]` in calldata

We avoid `abi.decode` of the dynamic array — direct calldata slicing keeps gas
predictable and lets us bound work. Layout (within the abi-encoded
`Operation` blob):

```
[0:32]     vt
[32:64]    offset to ops array head (== 0x40)
[64:96]    ops.length = N
[96:96+N*32]  per-call relative offsets (each points into the tail)
[...]      per-call tuples: (address to (32), uint256 value (32),
           bytes data offset (32), then data { len(32), bytes payload, pad })
```

`OpsCalldataLib`:

- `count(opsBlob) → uint256`
- `callAt(opsBlob, i) → (address to, uint256 value, bytes calldata data)`
- iterates in O(N), N capped at `MAX_OPS = 16`.

## Adversarial test cases

For the base policy and Relay subclass, cover at minimum:

- digest mismatch (wrong name/version/IE address/chainId)
- variant byte > 0
- `account` in data ≠ `account` arg
- `hasGasRefund=1` but `NO_GASREFUND` typehash used (forgery)
- `gasRefund.token` not whitelisted
- `exchangeRate > maxExchangeRate`
- `requireGasRefund=true` and `hasGasRefund=0`
- empty `Ops[]`
- `N > MAX_OPS`
- per-call: wrong `to`, wrong selector, `value != 0` for non-router target,
  approve `spender != relayRouter`, transfer `to ∉ recipient whitelist`
- malformed calldata (truncated, oversized offsets) — must revert cleanly

## Not in v1

- `MultiChainOps` validation (typehash + merkle insert) — scaffold but disabled
- CCTP / Rhino subclasses
- gas-refund settlement variant detection (settle vs callback)
- `recipient` ACL for `multicall(... refundTo, nftRecipient ...)` — comes when we
  parse Relay multicall params
