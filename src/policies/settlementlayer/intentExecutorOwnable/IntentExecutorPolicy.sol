// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { Ownable } from "solady/auth/Ownable.sol";

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

/// @dev Per-(configId, account) record for one opted-in layer. Adapter address is frozen
///      at install time so a later owner swap doesn't change behaviour for this session.
struct LayerStamp {
    bytes32 layerId;
    address adapter;
    bytes32 configHash;
}

struct PolicyStorage {
    LayerStamp[] layers;
    mapping(bytes32 layerId => bytes config) configs;
    mapping(bytes32 layerId => bool enabled) hasLayer;
}

/// @title IntentExecutorPolicy
/// @author Rhinestone
/// @notice Owner-managed IntentExecutor policy. Combines two roles in one contract:
///         (1) the **registry** of `IIntentExecutorAdapter` implementations addressed by
///         `layerId`, mutable by the owner; (2) the **policy** smart-sessions installs
///         against, which freezes the adapter set chosen at install time and dispatches
///         per-call validation to those adapters.
///
/// @dev    Trust model:
///         • Owner can register / overwrite / remove adapters for `layerId`s in the
///           registry. This affects only **future** installs — already-installed sessions
///           keep the adapter addresses they stamped in.
///         • New settlement layer? Owner deploys + registers an adapter; a session needs
///           to be re-installed (with the new layer in its init blob) to use it.
///         • To get pure immutability, use `StaticIntentExecutorPolicy` instead.
///
///         Data blob layout extends the base format with a per-call layer-hint vector
///         APPENDED AFTER the ABI-encoded Operation:
///
///         ┌──────────────────────────────────────────────────────────────┐
///         │  base header  (see BaseIntentExecutorPolicy._validateClaim)  │
///         │  ABI-encoded Operation                                        │
///         │  --- ownable extension ---                                   │
///         │  [last 1 + N bytes of `data`]                                 │
///         │      callCount (uint8) || layerHints (uint8 × callCount)     │
///         └──────────────────────────────────────────────────────────────┘
///
///         Each `layerHint` indexes into `layers` (NOT a free-form `layerId`); the index
///         is bounded by the install-time layer count, so an attacker can't smuggle in a
///         new layer at signature time.
///
///         Init data layout (after the base header):
///         ┌──────────────────────────────────────────────────────────────┐
///         │  [0]    layerCount (uint8)                                   │
///         │  per layer:                                                  │
///         │    [..]  layerId (bytes32)                                   │
///         │    [..]  configLen (uint16)                                  │
///         │    [..]  configBytes (configLen bytes)                       │
///         └──────────────────────────────────────────────────────────────┘
contract IntentExecutorPolicy is BaseIntentExecutorPolicy, Ownable {
    bytes32 internal constant POLICY_STORAGE_POSITION =
        keccak256("rhinestone.storage.IntentExecutorPolicy.v1");

    /// @dev Owner-managed catalogue. Reads at install time; writes never affect already-
    ///      installed sessions.
    mapping(bytes32 layerId => address adapter) public adapterFor;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Owner registered an adapter under a `layerId` that the adapter itself
    ///         doesn't claim. Catches honest mistakes; the adapter's own `layerId()` is
    ///         the source of truth.
    error LayerIdMismatch(bytes32 declared, bytes32 adapterClaim);
    /// @notice Install referenced a `layerId` not in the registry at install time.
    error UnknownLayer(bytes32 layerId);
    /// @notice Init blob ended before reading a full layer record.
    error OwnableInitTruncated(uint256 expected, uint256 got);
    /// @notice Layer-hint vector at the tail of the data blob is shorter than the call
    ///         count (corrupt or truncated payload).
    error LayerHintsTruncated(uint256 callCount, uint256 dataLength);
    /// @notice Layer-hint indexes past `layers.length`.
    error LayerHintOutOfRange(uint256 callIndex, uint8 hint, uint256 layersInstalled);
    /// @notice The adapter validation reverted; the inner reason bytes are forwarded.
    /// @dev    `reason` retains the adapter's typed error selector — callers and indexers
    ///         can decode it with the adapter's ABI.
    error AdapterRejected(uint256 callIndex, bytes32 layerId, bytes reason);
    /// @notice Same layer listed twice in the install blob.
    error DuplicateLayerInstall(bytes32 layerId);

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event AdapterSet(bytes32 indexed layerId, address indexed adapter);
    event AdapterRemoved(bytes32 indexed layerId, address indexed previousAdapter);

    constructor(address owner_) {
        _initializeOwner(owner_);
    }

    /*//////////////////////////////////////////////////////////////
                              REGISTRY (OWNER)
    //////////////////////////////////////////////////////////////*/

    /// @notice Registers (or overwrites) the adapter for a layer.
    /// @dev Calls `adapter_.layerId()` and reverts when the bytecode's self-declared id
    ///      doesn't match `layerId`. This catches mis-registrations at write time rather
    ///      than at session install time (where the failure would be much more confusing).
    function setAdapter(bytes32 layerId, address adapter_) external onlyOwner {
        bytes32 claim = IIntentExecutorAdapter(adapter_).layerId();
        if (claim != layerId) revert LayerIdMismatch(layerId, claim);
        adapterFor[layerId] = adapter_;
        emit AdapterSet(layerId, adapter_);
    }

    function removeAdapter(bytes32 layerId) external onlyOwner {
        address prev = adapterFor[layerId];
        if (prev == address(0)) revert UnknownLayer(layerId);
        delete adapterFor[layerId];
        emit AdapterRemoved(layerId, prev);
    }

    /*//////////////////////////////////////////////////////////////
                              INSTALL
    //////////////////////////////////////////////////////////////*/

    function _initializeSubclass(
        IntentExecutorStorage storage $,
        address account,
        ConfigId configId,
        bytes calldata tail
    )
        internal
        override
    {
        if (tail.length < 1) revert OwnableInitTruncated(1, tail.length);
        uint8 layerCount = uint8(tail[0]);
        PolicyStorage storage ps = _policyStorage(configId, account);

        uint256 cursor = 1;
        for (uint256 i; i < layerCount; i++) {
            if (tail.length < cursor + 34) revert OwnableInitTruncated(cursor + 34, tail.length);
            bytes32 lid = bytes32(tail[cursor:cursor + 32]);
            cursor += 32;
            uint16 cfgLen = uint16(bytes2(tail[cursor:cursor + 2]));
            cursor += 2;
            if (tail.length < cursor + uint256(cfgLen)) {
                revert OwnableInitTruncated(cursor + uint256(cfgLen), tail.length);
            }
            bytes calldata cfg = tail[cursor:cursor + uint256(cfgLen)];
            cursor += uint256(cfgLen);

            if (ps.hasLayer[lid]) revert DuplicateLayerInstall(lid);

            address adapter = adapterFor[lid];
            if (adapter == address(0)) revert UnknownLayer(lid);

            // Fail-fast: malformed config blob at install instead of at first signature.
            IIntentExecutorAdapter(adapter).validateConfig(cfg);

            ps.layers.push(
                LayerStamp({ layerId: lid, adapter: adapter, configHash: keccak256(cfg) })
            );
            ps.configs[lid] = bytes(cfg);
            ps.hasLayer[lid] = true;
        }

        if (tail.length != cursor) revert IntentExecutorConfigLib.InvalidConfigData();
        $.subclassSlot = POLICY_STORAGE_POSITION;
    }

    /*//////////////////////////////////////////////////////////////
                              VALIDATION
    //////////////////////////////////////////////////////////////*/

    function _validateOps(
        ConfigId configId,
        address account,
        IntentExecutorStorage storage,
        Execution[] calldata calls,
        bytes calldata data
    )
        internal
        view
        override
    {
        PolicyStorage storage ps = _policyStorage(configId, account);
        uint256 n = calls.length;
        if (n == 0) return;

        bytes calldata hints = _readLayerHints(data, n);
        uint256 layersLen = ps.layers.length;

        for (uint256 i; i < n; i++) {
            uint8 hint = uint8(hints[i]);
            if (uint256(hint) >= layersLen) revert LayerHintOutOfRange(i, hint, layersLen);
            LayerStamp memory stamp = ps.layers[hint];
            bytes memory cfg = ps.configs[stamp.layerId];
            // Adapter is `view` and stateless; try/catch so we can attach the raw
            // adapter revert reason to `AdapterRejected`.
            try IIntentExecutorAdapter(stamp.adapter).validateCall(
                stamp.configHash, cfg, i, calls[i]
            ) {
                continue;
            } catch (bytes memory reason) {
                revert AdapterRejected(i, stamp.layerId, reason);
            }
        }
    }

    /// @notice Slices the layer-hint vector from the tail of the data blob.
    /// @dev    Layout: `... ABI(Operation) || callCount(uint8) || hint[0] || ... || hint[N-1]`
    ///         where `N == callCount`. We trust `callCount` and use `data.length` to
    ///         locate the vector — relative to the bytes calldata, not msg.data, so ABI
    ///         padding around `data` doesn't matter.
    function _readLayerHints(
        bytes calldata data,
        uint256 callCount
    )
        private
        pure
        returns (bytes calldata hints)
    {
        if (data.length < callCount + 1) revert LayerHintsTruncated(callCount, data.length);
        uint256 headerByte = data.length - callCount - 1;
        if (uint8(data[headerByte]) != callCount) {
            // The header byte is what tells us where the vector starts; a mismatch with
            // the actual ops count means the relayer mis-built the blob and we refuse
            // to fall back to a guess.
            revert LayerHintsTruncated(callCount, data.length);
        }
        hints = data[headerByte + 1:];
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    function getInstalledLayers(
        ConfigId configId,
        address account
    )
        external
        view
        returns (LayerStamp[] memory list)
    {
        list = _policyStorage(configId, account).layers;
    }

    function getLayerConfig(
        ConfigId configId,
        address account,
        bytes32 layerId
    )
        external
        view
        returns (bytes memory)
    {
        return _policyStorage(configId, account).configs[layerId];
    }

    function _policyStorage(
        ConfigId configId,
        address account
    )
        private
        view
        returns (PolicyStorage storage ps)
    {
        bytes32 base = POLICY_STORAGE_POSITION;
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
            ps.slot := slot
        }
    }
}
