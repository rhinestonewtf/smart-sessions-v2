// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IPermit2SenderPolicy } from "@policies/claim/permit2/interfaces/IPermit2SenderPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Permit2 Sender Policy
/// @author Rhinestone
/// @notice ERC-1271 policy that accepts a signed request only when Permit2 is the sender
/// @dev Stateless. Install it on a session's ERC-1271 list only, beside a `Permit2ClaimPolicy`:
///      that policy bounds what the signed claim may contain, this one bounds who may present it.
///      It does not bind the digest, so it must never be the only policy on the list.
///      Every 1271 check from another sender is refused, including an intent executor's check of
///      pre-claim ops in an ERC-1271 signature mode; validate those through `verifyExecution`.
///      One-time-use sessions get the same sender rule from `OneTimeUseIdPolicy`.
contract Permit2SenderPolicy is I1271Policy, IPermit2SenderPolicy {
    /// @notice The Permit2 deployment: the only ERC-1271 request sender this policy accepts
    ISignatureTransfer public immutable PERMIT2;

    /// @param permit2 The Permit2 deployment
    constructor(ISignatureTransfer permit2) {
        // Claim sub-policy slots pass a zero sender, so a zero PERMIT2 would accept them.
        if (address(permit2) == address(0)) revert InvalidPermit2();
        PERMIT2 = permit2;
    }

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Takes no configuration; the accepted sender is fixed at deployment
    function initializeWithMultiplexer(
        address,
        ConfigId,
        bytes calldata initData
    )
        external
        pure
        override
    {
        if (initData.length != 0) revert InvalidInitDataLength(initData.length);
    }

    /*//////////////////////////////////////////////////////////////
                             1271 VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Accepts the request only when Permit2 sent it
    /// @param requestSender The caller of the account's `isValidSignature`
    /// @return True if `requestSender` is Permit2
    function check1271SignedAction(
        ConfigId,
        address requestSender,
        address,
        bytes32,
        bytes calldata
    )
        external
        view
        override
        returns (bool)
    {
        return requestSender == address(PERMIT2);
    }

    /*//////////////////////////////////////////////////////////////
                                 ERC165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-165 for the 1271 policy surface only
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(I1271Policy).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
