// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @notice Per-(multiplexer, configId, account) storage for the IntentExecutor policy family.
/// @dev Held at a diamond slot derived from the same recipe BaseClaimPolicy uses, so policy
///      installation and isolation behave identically to the claim policies.
struct IntentExecutorStorage {
    /// @dev Address of the `StandaloneIntentExecutor` contract. Pinned at init.
    ///      Used as the `verifyingContract` field of the EIP-712 domain.
    ///      A non-zero value is treated as initialized.
    address intentExecutor;
    /// @dev Compact flag byte. See `IntentExecutorDataTypes.sol`.
    uint8 flags;
    /// @dev Account pinned at init when `FLAG_LOCK_ACCOUNT` is set.
    address pinnedAccount;
    /// @dev Upper bound on `GasRefund.exchangeRate`. `0` means "no cap" only when
    ///      `FLAG_REQUIRE_GAS_REFUND` is not set (otherwise an exchangeRate of 0 still
    ///      survives the inequality but is filtered by the typehash check).
    uint256 maxExchangeRate;
    /// @dev Set of permitted `GasRefund.token` values. Empty set = any token allowed
    ///      (subject to `maxExchangeRate`). Only consulted when the signed digest
    ///      carries a non-zero GasRefund typehash.
    EnumerableSetLib.AddressSet gasTokenWhitelist;
    /// @dev Reserved slot the subclass uses to store its own settlement-layer config.
    ///      Subclasses access this via their own `using ... for IntentExecutorStorage`
    ///      extensions rather than nesting another struct here, so we don't need to
    ///     track an upgrade-safe layout for every concrete subclass.
    bytes32 subclassSlot;
}

/// @title IntentExecutorStorageLib
/// @notice Diamond-storage accessor for `IntentExecutorStorage`.
/// @dev Slot derivation mirrors `BaseStorageLib` so storage isolation rules are unchanged.
library IntentExecutorStorageLib {
    /// @dev `keccak256("rhinestone.storage.IntentExecutorPolicy") - 1`.
    bytes32 internal constant STORAGE_POSITION =
        0xef33895c247a3d541586536055acd258c615502e2318a84e5cdcfe3e50705fde;

    /// @notice Returns the storage pointer for an `IntentExecutorStorage` triple.
    function getStorage(
        ConfigId id,
        address account,
        address multiplexer
    )
        internal
        pure
        returns (IntentExecutorStorage storage $)
    {
        bytes32 slot = _slot(STORAGE_POSITION, id, account, multiplexer);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := slot
        }
    }

    function _slot(
        bytes32 baseSlot,
        ConfigId id,
        address account,
        address multiplexer
    )
        private
        pure
        returns (bytes32 slot)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(0x00, baseSlot)
            mstore(0x20, multiplexer)
            mstore(0x40, id)
            mstore(0x60, account)
            slot := keccak256(0x00, 0x80)
            mstore(0x40, ptr)
            mstore(0x60, 0x00)
        }
    }
}
