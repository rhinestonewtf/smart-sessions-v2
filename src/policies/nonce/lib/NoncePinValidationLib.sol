// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { PinnedNonce, NONCE_START, NONCE_END } from "@policies/nonce/types/NoncePinDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                         VALIDATION LOGIC
//////////////////////////////////////////////////////////////

A bridge session may permit two settlement families that keep separate
consumables. Neither reads the other, so each surface reads across:

┌──────────────────┬───────────────────────┬────────────────────────┐
│  surface         │  own consumable       │  reads                 │
├──────────────────┼───────────────────────┼────────────────────────┤
│  Permit2 claim   │  Permit2 bitmap       │  executor slot         │
│  executor action │  executor slot        │  Permit2 bitmap        │
└──────────────────┴───────────────────────┴────────────────────────┘

Each reads only the OTHER family's consumable. Both settlement layers
consume their nonce before validating a signature, so a check on one's own
would reject the very settlement being validated.

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
        IStandaloneIntentExecutor executor,
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

        return !executor.isStandaloneIntentNonceConsumed(pinned, account);
    }

    /// @notice Checks the pinned nonce has not been spent on Permit2
    /// @dev Fails closed when unconfigured. Needs no payload: the nonce comes from configuration
    /// @param $pinned Storage pointer to the pinned nonce
    /// @param permit2 The Permit2 deployment to consult
    /// @param account The account being validated
    /// @return True if the action may proceed
    function validateAction(
        PinnedNonce storage $pinned,
        ISignatureTransfer permit2,
        address account
    )
        internal
        view
        returns (bool)
    {
        if (!$pinned.configured) return false;

        uint256 pinned = $pinned.nonce;
        uint256 word = permit2.nonceBitmap(account, pinned >> 8);

        return word & (uint256(1) << (pinned & 0xff)) == 0;
    }
}
