// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ConfigId } from "@smartsessions/DataTypes.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";

/// @title One Time Use Id Storage Library
/// @author Rhinestone
/// @notice Namespaced storage for OneTimeUseIdPolicy: the pinned id per configuration, the durable
///         spend per (multiplexer, account, id), and the transient per-transaction records the
///         burn's validation leaves behind.
library OneTimeUseIdStorageLib {
    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.pin") - 1
    bytes32 internal constant PIN_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.pin")) - 1);

    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.spend") - 1
    bytes32 internal constant SPEND_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.spend")) - 1);

    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.nomination") - 1
    bytes32 internal constant NOMINATION_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.nomination")) - 1);

    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.burnedInTx") - 1
    bytes32 internal constant BURNED_IN_TX_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.burnedInTx")) - 1);

    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.validated") - 1
    bytes32 internal constant VALIDATED_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.validated")) - 1);

    /// @dev Nomination value meaning no settlement was nominated in this transaction
    uint256 internal constant NOT_NOMINATED = 0;

    /// @dev Deadline value meaning the pinned id never expires
    uint256 internal constant NO_DEADLINE = 0;

    /// @dev Burn kinds: none, a `consume`, or a `consumeFor`
    uint256 internal constant BURN_NONE = 0;
    uint256 internal constant BURN_CONSUME = 1;
    uint256 internal constant BURN_CONSUME_FOR = 2;

    /// @dev Zero id means "not configured"; zero deadline means "never expires"
    struct PinStorage {
        uint256 id;
        uint256 deadline;
    }

    struct SpendStorage {
        bool burned;
    }

    /// @notice The pinned id for a (configId, multiplexer, account)
    function pin(
        ConfigId configId,
        address multiplexer,
        address account
    )
        internal
        pure
        returns (PinStorage storage $)
    {
        bytes32 slot = EfficientHashLib.hash(
            PIN_POSITION,
            ConfigId.unwrap(configId),
            bytes32(uint256(uint160(multiplexer))),
            bytes32(uint256(uint160(account)))
        );
        assembly {
            $.slot := slot
        }
    }

    /// @notice The durable spend for (multiplexer, account, id). Keyed by the multiplexer because
    ///         `checkAction` is permissionless: anyone can pin the account's id under their own
    ///         address and "burn" it there, which must not touch the record the real multiplexer
    ///         reads. Not keyed by configId so every action slot of one session shares one spend.
    function spendRecord(
        address multiplexer,
        address account,
        uint256 id
    )
        internal
        pure
        returns (SpendStorage storage $)
    {
        bytes32 slot = _key(SPEND_POSITION, multiplexer, account, id);
        assembly {
            $.slot := slot
        }
    }

    /// @notice Whether `deadline` has passed. Inclusive, matching Permit2's own
    ///         `block.timestamp > deadline` rule, so a settlement is still valid in the block the
    ///         deadline names. One predicate for both the install-time rejection and the two read
    ///         surfaces, so install refuses exactly the deadlines the reads would already refuse.
    function isExpired(uint256 deadline) internal view returns (bool) {
        return deadline != NO_DEADLINE && block.timestamp > deadline;
    }

    /// @notice Hashed so no witness value collides with NOT_NOMINATED; the (unreachable) zero hash
    ///         is remapped to 1 so the invariant holds without relying on "practically impossible".
    function nominationOf(uint256 witness) internal pure returns (uint256 value) {
        value = uint256(EfficientHashLib.hash(bytes32(witness)));
        if (value == NOT_NOMINATED) value = 1;
    }

    /// @notice Records, for this transaction, the settlement the burn of `id` nominated
    function setNomination(
        address multiplexer,
        address account,
        uint256 id,
        uint256 value
    )
        internal
    {
        bytes32 slot = _key(NOMINATION_POSITION, multiplexer, account, id);
        assembly ("memory-safe") {
            tstore(slot, value)
        }
    }

    /// @notice The nomination the burn of `id` recorded in this transaction, or NOT_NOMINATED
    function nomination(
        address multiplexer,
        address account,
        uint256 id
    )
        internal
        view
        returns (uint256 value)
    {
        bytes32 slot = _key(NOMINATION_POSITION, multiplexer, account, id);
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }

    /// @notice Marks, for this transaction, that the session's burn of `id` was validated under
    ///         `multiplexer`, and which burn it was
    function setBurnedInTx(
        address multiplexer,
        address account,
        uint256 id,
        uint256 kind
    )
        internal
    {
        bytes32 slot = _key(BURNED_IN_TX_POSITION, multiplexer, account, id);
        assembly ("memory-safe") {
            tstore(slot, kind)
        }
    }

    /// @notice Which burn of `id` was validated under `multiplexer` earlier in this transaction:
    ///         BURN_NONE, BURN_CONSUME or BURN_CONSUME_FOR
    function burnedInTx(
        address multiplexer,
        address account,
        uint256 id
    )
        internal
        view
        returns (uint256 kind)
    {
        bytes32 slot = _key(BURNED_IN_TX_POSITION, multiplexer, account, id);
        assembly ("memory-safe") {
            kind := tload(slot)
        }
    }

    /// @notice Marks, for this transaction, that a burn of `id` for `account` passed validation
    ///         under some multiplexer. Read by the execution-time `consume`/`consumeFor`, which
    ///         know the account (their caller) but not the multiplexer.
    function setValidated(address account, uint256 id) internal {
        bytes32 slot = EfficientHashLib.hash(
            VALIDATED_POSITION, bytes32(uint256(uint160(account))), bytes32(id)
        );
        assembly ("memory-safe") {
            tstore(slot, 1)
        }
    }

    /// @notice Whether a burn of `id` for `account` passed validation in this transaction
    function validated(address account, uint256 id) internal view returns (bool yes) {
        bytes32 slot = EfficientHashLib.hash(
            VALIDATED_POSITION, bytes32(uint256(uint160(account))), bytes32(id)
        );
        assembly ("memory-safe") {
            yes := tload(slot)
        }
    }

    function _key(
        bytes32 position,
        address multiplexer,
        address account,
        uint256 id
    )
        private
        pure
        returns (bytes32)
    {
        return EfficientHashLib.hash(
            position,
            bytes32(uint256(uint160(multiplexer))),
            bytes32(uint256(uint160(account))),
            bytes32(id)
        );
    }
}
