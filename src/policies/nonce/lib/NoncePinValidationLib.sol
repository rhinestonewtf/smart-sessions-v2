// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IIntentExecutorNonces } from "@policies/nonce/interfaces/IIntentExecutorNonces.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { PinnedNonce, NONCE_START, NONCE_END } from "@policies/nonce/types/NoncePinDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                         VALIDATION LOGIC
//////////////////////////////////////////////////////////////

A bridge session may permit two settlement families that keep separate
consumables. Neither reads the other, so each surface must first establish
that the settlement in front of it is the pinned one, then exclude the rest:

┌──────────────────┬──────────────────────────┬──────────────────────────┐
│  surface         │  binds the settlement    │  excludes                │
├──────────────────┼──────────────────────────┼──────────────────────────┤
│  Permit2 claim   │  nonce in the payload    │  all executor families   │
│  executor action │  nonce reported in flight│  other executor families │
│                  │                          │  + Permit2 bitmap        │
└──────────────────┴──────────────────────────┴──────────────────────────┘

Binding is what a consumed-nonce read cannot do. Consumption is permanent, so
once the pinned nonce is burned it reads the same for every later settlement;
the executor therefore reports the nonce in flight only while it validates.
Uniqueness then comes from the settlement layers themselves, which each refuse
a second burn of the same nonce.

//////////////////////////////////////////////////////////////*/

/// @title Nonce Pin Validation Library
/// @author Rhinestone
/// @notice Validation logic for pinning a nonce and excluding the other settlement family
library NoncePinValidationLib {
    /// @notice Checks a Permit2 claim carries the pinned nonce and the executor has not settled
    /// @dev Fails closed when unconfigured or when the payload cannot contain a nonce
    /// @param $pinned Storage pointer to the pinned nonce
    /// @param executor The intent executor to consult for an executor-side settlement
    /// @param account The account being validated
    /// @param signature The Permit2 claim payload
    /// @return True if the claim may proceed
    function validateClaim(
        PinnedNonce storage $pinned,
        IIntentExecutorNonces executor,
        address account,
        bytes calldata signature
    )
        internal
        view
        returns (bool)
    {
        if (!$pinned.configured) return false;
        if (signature.length < NONCE_END) return false;

        uint256 pinned = $pinned.nonce;
        if (uint256(bytes32(signature[NONCE_START:NONCE_END])) != pinned) return false;

        // Every family counts, unconditionally. isIntentNonceSettledElsewhere would skip whichever
        // family is mid-validation, which is what the action surface wants and the opposite of
        // what this one does: a claim reached while an executor settlement is in flight must see
        // that settlement's burn, not have it excluded.
        return !executor.isStandaloneIntentNonceConsumed(pinned, account)
            && !executor.isPermit2IntentNonceConsumed(pinned, account)
            && !executor.isCompactIntentNonceConsumed(pinned, account);
    }

    /// @notice Checks the executor settlement in flight is the pinned one and stands alone
    /// @dev Fails closed when unconfigured. Rejects any action reached outside an executor
    ///      settlement, which includes every plain userOp under the same permission
    /// @param $pinned Storage pointer to the pinned nonce
    /// @param executor The intent executor whose in-flight settlement is being validated
    /// @param permit2 The Permit2 deployment to consult
    /// @param account The account being validated
    /// @return True if the action may proceed
    function validateAction(
        PinnedNonce storage $pinned,
        IIntentExecutorNonces executor,
        ISignatureTransfer permit2,
        address account
    )
        internal
        view
        returns (bool)
    {
        if (!$pinned.configured) return false;

        uint256 pinned = $pinned.nonce;

        // Bind: every execution of this settlement reports the same nonce, and a settlement on
        // any other nonce reports that one, so a batch passes as a unit and nothing else does.
        // The account is checked too - a nonce without its owner would match a settlement for
        // somebody else that happens to carry this pin.
        (bool active, address settling, uint256 inFlight) = executor.currentIntentNonce();
        if (!active || settling != account || inFlight != pinned) return false;

        if (executor.isIntentNonceSettledElsewhere(pinned, account)) return false;

        uint256 word = permit2.nonceBitmap(account, pinned >> 8);

        return word & (uint256(1) << (pinned & 0xff)) == 0;
    }
}
