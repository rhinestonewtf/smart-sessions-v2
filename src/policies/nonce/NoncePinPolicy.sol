// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { INoncePinPolicy } from "@policies/nonce/interfaces/INoncePinPolicy.sol";
import { I1271Policy, IActionPolicy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { IIntentExecutorNonces } from "@policies/nonce/interfaces/IIntentExecutorNonces.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Libraries
import { NoncePinStorageLib } from "@policies/nonce/lib/NoncePinStorageLib.sol";
import { NoncePinValidationLib } from "@policies/nonce/lib/NoncePinValidationLib.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PinnedNonce } from "@policies/nonce/types/NoncePinDataTypes.sol";

// forgefmt: disable-start
/// @title Nonce Pin Policy
/// @author Rhinestone
/// @notice Pins one nonce for a session and refuses wherever it has already been spent
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                            Why this exists                              │
/// │                                                                         │
/// │  A policy here is `view` and cannot record that a session was spent,    │
/// │  so one-time use borrows a consumable the settlement layer already      │
/// │  burns. The signer picks the nonce, so without pinning it can mint a    │
/// │  fresh digest per nonce and spend repeatedly — each spend individually  │
/// │  replay-protected, the session unbounded.                               │
/// │                                                                         │
/// │  Pinning collapses every digest a session can produce into competing    │
/// │  for one slot. What makes that bite is refusing a settlement that       │
/// │  carries any other nonce: the first settlement on the pin burns it,     │
/// │  and the rest revert inside the settlement layer, before any policy     │
/// │  runs. Refusing on the pin alone would not — a consumable read is       │
/// │  permanent, so once burned it answers the same for every settlement     │
/// │  that follows, whatever nonce it carries.                               │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// @dev A bridge session may permit two settlement families that keep separate consumables:
///      Permit2 records a bitmap, the intent executor a mapping. Neither reads the other, so this
///      policy answers on both surfaces, and each binds the settlement in front of it before
///      excluding the other family.
/// @dev Register alongside Permit2ClaimPolicy on the claim surface. Alone it proves nothing: it
///      reads a caller-supplied slice, and only the claim policy binds that slice to the digest.
/// @dev The action surface is for executor settlements only. It refuses any action that did not
///      consume the pinned nonce on the executor, so a plain userOp under the same permission is
///      rejected; pair it with a policy that constrains the call itself, since this one does not.
/// @dev Limits, all of them real: the guarantee is per chain, not per session; any whitelisted
///      arbiter can end the session by submitting the claim with every requested amount set to
///      zero, since Permit2 burns the nonce before it reads the unsigned transfer details; any
///      co-installed session key can likewise burn the executor slot for the pinned nonce, which
///      is keyed on (account, nonce) alone; and it bounds settlements, not signature validations.
// forgefmt: disable-end
contract NoncePinPolicy is INoncePinPolicy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using NoncePinStorageLib for ConfigId;
    using NoncePinValidationLib for PinnedNonce;

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The intent executor whose consumed nonces mark an executor settlement
    IIntentExecutorNonces public immutable INTENT_EXECUTOR;

    /// @notice The Permit2 deployment whose bitmap marks an arbiter settlement
    ISignatureTransfer public immutable PERMIT2;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param intentExecutor The intent executor to consult for executor-side settlements
    /// @param permit2 The Permit2 deployment to consult for arbiter-side settlements
    constructor(address intentExecutor, address permit2) {
        INTENT_EXECUTOR = IIntentExecutorNonces(intentExecutor);
        PERMIT2 = ISignatureTransfer(permit2);
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicy
    /// @notice Pins the nonce for a configuration, overwriting any existing entry
    /// @param account The account this configuration belongs to
    /// @param configId The configuration ID
    /// @param initData The nonce to pin, as a single 32-byte word
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        if (initData.length != 32) revert InvalidInitDataLength(initData.length);

        PinnedNonce storage $pinned =
            configId.getStorage({ account: account, multiplexer: msg.sender });

        $pinned.configured = true;
        $pinned.nonce = uint256(bytes32(initData[0:32]));

        emit PolicySet(configId, msg.sender, account);
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNATURE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc I1271Policy
    /// @notice Checks the claim carries the pinned nonce and the executor has not settled
    /// @dev Returns false rather than reverting; the surrounding policy list decides the outcome
    /// @return True if the claim may proceed
    function check1271SignedAction(
        ConfigId id,
        address, /* requestSender */
        address account,
        bytes32, /* hash */
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        PinnedNonce storage $pinned = id.getStorage({ account: account, multiplexer: msg.sender });

        return $pinned.validateClaim(INTENT_EXECUTOR, account, signature);
    }

    /*//////////////////////////////////////////////////////////////
                           ACTION VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IActionPolicy
    /// @notice Permits one executor settlement, on the pinned nonce, while Permit2 is unspent
    /// @dev Needs no payload: the executor reports the nonce it is settling, so the calldata is
    ///      never read. An action reached outside a settlement reports nothing and is refused
    /// @return VALIDATION_SUCCESS if the action may proceed, VALIDATION_FAILED otherwise
    function checkAction(
        ConfigId id,
        address account,
        address, /* target */
        uint256, /* value */
        bytes calldata /* data */
    )
        external
        view
        override
        returns (uint256)
    {
        PinnedNonce storage $pinned = id.getStorage({ account: account, multiplexer: msg.sender });

        return $pinned.validateAction(INTENT_EXECUTOR, PERMIT2, account)
            ? VALIDATION_SUCCESS
            : VALIDATION_FAILED;
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INoncePinPolicy
    function getPinnedNonce(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        override
        returns (bool configured, uint256 nonce)
    {
        PinnedNonce storage $pinned =
            configId.getStorage({ account: account, multiplexer: multiplexer });

        return ($pinned.configured, $pinned.nonce);
    }

    /*//////////////////////////////////////////////////////////////
                                 ERC165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC165 interface support
    /// @dev Probed at install time; a wrong id makes the policy uninstallable on that surface
    /// @param interfaceId The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
