// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";

import {
    BaseIntentExecutorPolicy
} from "@policies/settlementlayer/shared/BaseIntentExecutorPolicy.sol";
import {
    IntentExecutorStorage
} from "@policies/settlementlayer/shared/lib/IntentExecutorStorageLib.sol";
import {
    IntentExecutorConfigLib
} from "@policies/settlementlayer/shared/lib/IntentExecutorConfigLib.sol";
import {
    IIntentExecutorAdapter
} from "@policies/settlementlayer/shared/interfaces/IIntentExecutorAdapter.sol";

/// @title StaticIntentExecutorPolicy
/// @author Rhinestone
/// @notice Fixed-bytecode IntentExecutor policy hard-wired to a single
///         `IIntentExecutorAdapter`. The adapter address is **immutable**: once deployed,
///         no governance action can change the validation rules. Install one per
///         settlement layer you want a given session to authorise.
///
/// @dev    Per-(configId, account) we store the adapter's config blob plus its install-time
///         hash so the adapter can attest against tampering. The adapter contract is
///         stateless; we re-pass `config` on every validation.
///
///         Init data layout (after the base header):
///         ┌──────────────────────────────────────────────────────────────┐
///         │  the adapter's config blob, verbatim                         │
///         └──────────────────────────────────────────────────────────────┘
contract StaticIntentExecutorPolicy is BaseIntentExecutorPolicy {
    /// @dev The single adapter this policy delegates per-call ACL to.
    IIntentExecutorAdapter public immutable ADAPTER;

    /// @dev Storage slot prefix for the per-install config blob. See
    ///      `_configStorage` for the keccak recipe.
    bytes32 internal constant STATIC_STORAGE_POSITION =
        keccak256("rhinestone.storage.StaticIntentExecutorPolicy.v1");

    struct StaticPolicyStorage {
        bytes config;
        bytes32 configHash;
    }

    constructor(IIntentExecutorAdapter adapter) {
        ADAPTER = adapter;
    }

    /// @notice The adapter's `layerId()` — convenience getter for off-chain indexers.
    function layerId() external view returns (bytes32) {
        return ADAPTER.layerId();
    }

    function _initializeSubclass(
        IntentExecutorStorage storage $,
        address account,
        ConfigId configId,
        bytes calldata tail
    )
        internal
        override
    {
        // Validate via the adapter — fail-fast on malformed config rather than at first
        // signature.
        ADAPTER.validateConfig(tail);
        StaticPolicyStorage storage ss = _configStorage(configId, account);
        ss.config = bytes(tail);
        ss.configHash = keccak256(tail);
        $.subclassSlot = STATIC_STORAGE_POSITION;
    }

    function _validateOps(
        ConfigId configId,
        address account,
        IntentExecutorStorage storage,
        Execution[] calldata calls,
        bytes calldata /* data */
    )
        internal
        view
        override
    {
        StaticPolicyStorage storage ss = _configStorage(configId, account);
        bytes memory config = ss.config;
        bytes32 hash = ss.configHash;
        // The adapter validates each call independently. We reach into the cached config
        // bytes once per call; this is intentional because adapters are pure functions of
        // their input and the bytes can't be hoisted across the staticcall boundary.
        uint256 n = calls.length;
        for (uint256 i; i < n; i++) {
            ADAPTER.validateCall(hash, config, i, calls[i]);
        }
    }

    function getConfig(ConfigId configId, address account) external view returns (bytes memory) {
        return _configStorage(configId, account).config;
    }

    function _configStorage(
        ConfigId configId,
        address account
    )
        private
        view
        returns (StaticPolicyStorage storage ss)
    {
        bytes32 base = STATIC_STORAGE_POSITION;
        bytes32 slot;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(0x00, base)
            mstore(0x20, caller())
            mstore(0x40, configId)
            mstore(0x60, account)
            slot := keccak256(0x00, 0x80)
            mstore(0x40, ptr)
            mstore(0x60, 0x00)
        }
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ss.slot := slot
        }
    }
}
