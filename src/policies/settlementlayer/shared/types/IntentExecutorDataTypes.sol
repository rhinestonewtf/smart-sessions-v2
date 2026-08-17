// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @dev Variant tag at byte 0 of the policy data blob.
uint8 constant VARIANT_SINGLE_CHAIN = 0;
uint8 constant VARIANT_MULTI_CHAIN = 1;

/// @dev Maximum number of (to, value, data) calls allowed inside a signed Operation.
/// @dev Bounds calldata walking gas. Picked to comfortably cover real Relay/CCTP/Rhino fills.
uint256 constant MAX_OPS = 16;

/// @dev Hard cap on raw calldata length of an individual call inside Operation.ops.
/// @dev Defense-in-depth against malicious offsets pointing far outside the blob.
uint256 constant MAX_INNER_CALLDATA = 64_000;

/// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address
/// verifyingContract)")`.
bytes32 constant EIP712_DOMAIN_TYPEHASH =
    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

/// @dev `keccak256("IntentExecutor")` — domain name for `StandaloneIntentExecutor`.
bytes32 constant INTENT_EXECUTOR_NAME_HASH =
    0xe8f220e6ef6da0729b62c6dafe214d6b61bfa6f1e0cf2d44529cfc517e939900;

/// @dev `keccak256("v0.0.1")` — domain version for `StandaloneIntentExecutor`.
bytes32 constant INTENT_EXECUTOR_VERSION_HASH =
    0x6bda7e3f385e48841048390444cced5cc795af87758af67622e5f4f0882c4a99;

/// @dev Matches `EIP712Lib.NO_GASREFUND`: `keccak256(abi.encode(TYPEHASH_GAS_REFUND, address(0),
/// 0))`.
bytes32 constant NO_GASREFUND = 0x2a2e93882f19103eba0384726c9f0fc4688a6ecb1e90bef28a42ac83bffe95d8;

/// @dev Compact configuration flags stored as a single uint8.
/// @dev Bit 0: require non-zero GasRefund. Bit 1: lock account binding.
uint8 constant FLAG_REQUIRE_GAS_REFUND = 1 << 0;
uint8 constant FLAG_LOCK_ACCOUNT = 1 << 1;
