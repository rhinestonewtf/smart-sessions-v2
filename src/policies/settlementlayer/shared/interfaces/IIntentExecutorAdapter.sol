// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

/// @title IIntentExecutorAdapter
/// @notice Pluggable adapter consumed by the ownable IntentExecutor policy. Adapters are
///         **stateless**: the policy stores opaque config bytes per (configId, account,
///         layerId) and passes them in on every validation call. This keeps adapters
///         freely upgradeable (deploy new bytecode, owner re-points the registry) without
///         needing storage migrations on the policy side.
///
///         Implementations validate a single `Execution` call from inside a signed
///         `Operation.ops` array. They MUST revert with a typed error on rejection — the
///         policy bubbles the revert reason up to the caller via `ADAPTER_REJECTED`. They
///         MUST NOT have side effects: `view` mode is required.
///
/// @dev   The interface intentionally avoids passing through `Execution[]` because the
///        per-call dispatch lets the policy fan-out checks across adapters when a
///        session opts in to multiple layers.
interface IIntentExecutorAdapter {
    /// @notice Stable identifier this adapter answers to (e.g. `keccak256("RELAY")`).
    /// @dev    Used by the policy to look up the right adapter for the call being
    ///         validated and by the registry as the primary key.
    function layerId() external pure returns (bytes32);

    /// @notice Validates a single inner call against the adapter's settlement-layer
    ///         ACL using the policy-stored config blob.
    /// @param configHash The keccak256 of the config blob — adapters that want to defend
    ///                   against config-blob tampering may verify against the on-chain
    ///                   commitment.
    /// @param config     The opaque config bytes stored by the policy at install time.
    /// @param callIndex  Position in the signed `Execution[]`, surfaced in error data.
    /// @param call       The single execution to authorize.
    /// @dev Reverts on rejection. Returning normally means "accept".
    function validateCall(
        bytes32 configHash,
        bytes calldata config,
        uint256 callIndex,
        Execution calldata call
    )
        external
        view;

    /// @notice Sanity-checks an install blob before the policy commits it to storage.
    ///         Intended to catch bad config (truncation, zero-addresses, ...) at install
    ///         time rather than at first use.
    function validateConfig(bytes calldata config) external view;
}
