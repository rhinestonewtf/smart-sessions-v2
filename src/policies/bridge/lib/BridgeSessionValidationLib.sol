// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IIntentExecutorNonces } from "@policies/bridge/interfaces/IIntentExecutorNonces.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import {
    BridgeSession,
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR,
    PERMIT2_NONCE_START,
    INTENT_EXECUTOR_NONCE_START,
    NONCE_LENGTH
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                         VALIDATION LOGIC
//////////////////////////////////////////////////////////////

Two things have to hold for a settlement to proceed:

  BIND       the settlement in front of us carries the pinned nonce, read from
             its own layer's payload at that layer's offset

  EXCLUDE    no OTHER layer has already spent that nonce

and one thing must NOT be checked: the consumable the settling layer itself
burns. The layers wired here burn before they validate, so a layer checking
its own consumable would reject the settlement it is validating, every time.

That exemption is per CONSUMABLE, not per layer, and the distinction matters:
the executor keeps three independent namespaces and a settlement burns exactly
one of them, so the other two remain real evidence of a prior spend. Nor is
burn-before-validate a universal law of the executor family - its compact
pre-claim path validates first and consumes after. The exemption is therefore
claimed only for the one namespace actually skipped, where the ordering has
been checked, rather than asserted for every layer.

Uniqueness within a layer is free - each settlement layer already refuses to
spend the same nonce twice, and does so before any policy runs. This library
only closes the cross-layer cases.

//////////////////////////////////////////////////////////////*/

/// @title Bridge Session Validation Library
/// @author Rhinestone
/// @notice Pins one nonce across every permitted settlement layer
library BridgeSessionValidationLib {
    /// @notice Where the nonce sits in a layer's payload
    /// @param layer The settlement layer
    /// @return start The offset of the nonce
    function nonceStart(uint8 layer) internal pure returns (uint256 start) {
        return layer == LAYER_PERMIT2 ? PERMIT2_NONCE_START : INTENT_EXECUTOR_NONCE_START;
    }

    /// @notice Checks the settlement carries the pinned nonce and no other layer has spent it
    /// @dev Fails closed when unconfigured, when the payload cannot contain a nonce, or when the
    ///      layer is not one this session permits
    /// @param $session Storage pointer to the bridge session
    /// @param executor The intent executor to consult
    /// @param permit2 The Permit2 deployment to consult
    /// @param layer The settlement layer this payload belongs to
    /// @param account The account being validated
    /// @param payload The layer's own claim payload, with the layer tag already stripped
    /// @return True if the settlement may proceed
    function validate(
        BridgeSession storage $session,
        IIntentExecutorNonces executor,
        ISignatureTransfer permit2,
        uint8 layer,
        address account,
        bytes calldata payload
    )
        internal
        view
        returns (bool)
    {
        if (!$session.configured) return false;

        uint256 start = nonceStart(layer);
        if (payload.length < start + NONCE_LENGTH) return false;

        // BIND: this settlement must be the pinned one
        uint256 pinned = $session.nonce;
        if (uint256(bytes32(payload[start:start + NONCE_LENGTH])) != pinned) return false;

        // EXCLUDE: every layer except the one settling
        return !spentElsewhere(executor, permit2, layer, pinned, account);
    }

    /// @notice Whether a layer other than the settling one has already spent this nonce
    /// @dev The settling layer is skipped because it burns before it validates, so its own
    ///      consumable already reads spent by the time this runs
    /// @param executor The intent executor to consult
    /// @param permit2 The Permit2 deployment to consult
    /// @param layer The settlement layer currently settling
    /// @param nonce The pinned nonce
    /// @param account The account being validated
    /// @return True if another layer has spent it
    function spentElsewhere(
        IIntentExecutorNonces executor,
        ISignatureTransfer permit2,
        uint8 layer,
        uint256 nonce,
        address account
    )
        internal
        view
        returns (bool)
    {
        if (layer != LAYER_PERMIT2 && permit2Spent(permit2, nonce, account)) return true;

        // The skip is per CONSUMABLE, not per layer. The executor keeps three independent
        // namespaces and a settlement through this layer burns only the standalone one, so only
        // that one may be skipped - the other two are spends this settlement did not make and
        // must still exclude it.
        if (
            layer != LAYER_INTENT_EXECUTOR
                && executor.isStandaloneIntentNonceConsumed(nonce, account)
        ) return true;
        if (executor.isPermit2IntentNonceConsumed(nonce, account)) return true;
        if (executor.isCompactIntentNonceConsumed(nonce, account)) return true;

        return false;
    }

    /// @notice Whether Permit2 has spent this nonce for this account
    /// @param permit2 The Permit2 deployment to consult
    /// @param nonce The nonce to check
    /// @param account The account the nonce belongs to
    /// @return True if the bit is set
    function permit2Spent(
        ISignatureTransfer permit2,
        uint256 nonce,
        address account
    )
        internal
        view
        returns (bool)
    {
        uint256 word = permit2.nonceBitmap(account, nonce >> 8);

        return word & (uint256(1) << (nonce & 0xff)) != 0;
    }

    /// @notice Whether the intent executor has spent this nonce in any of its three namespaces
    /// @param executor The intent executor to consult
    /// @param nonce The nonce to check
    /// @param account The account the nonce belongs to
    /// @return True if any namespace has consumed it
    function executorSpent(
        IIntentExecutorNonces executor,
        uint256 nonce,
        address account
    )
        internal
        view
        returns (bool)
    {
        return executor.isStandaloneIntentNonceConsumed(nonce, account)
            || executor.isPermit2IntentNonceConsumed(nonce, account)
            || executor.isCompactIntentNonceConsumed(nonce, account);
    }
}
