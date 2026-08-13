// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {
    IStandaloneIntentExecutor
} from "@rhinestone/compact-utils/src/executor/interfaces/IStandaloneIntent.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

// Libraries
import { Permit2HeaderLib } from "@policies/claim/permit2/lib/Permit2HeaderLib.sol";

/// @title Nonce Pin Policy
/// @author Rhinestone
/// @notice Constrains a Permit2 claim to one pre-agreed nonce, so every digest a session can
///         produce competes for a single consumable slot per chain.
/// @dev A 1271 policy is `view` and cannot record that a session was spent, so one-time use has
///      to borrow Permit2's nonce bitmap. The signer picks the nonce, so without pinning it can
///      mint a fresh digest per nonce and spend repeatedly.
/// @dev Register alongside Permit2ClaimPolicy. Alone this proves nothing: it reads a
///      caller-supplied slice, and only the claim policy binds that slice to the digest — which
///      is also what guarantees the slice is a Permit2 header rather than some other layout.
/// @dev Also refuses once the executor has settled on the same nonce. The two families keep
///      separate consumables — Permit2 a bitmap, the executor a mapping — so neither sees the
///      other. This closes the direction that leaks worst: an arbiter's pre-claim burn is
///      failure-tolerant, so without this an executor settlement would not stop a later one here.
/// @dev It cannot close the reverse direction; that needs a policy on the executor's own 1271
///      path, which is PR #46.
/// @dev Limits, all of them real: the guarantee is per chain, not per session; any whitelisted
///      arbiter can burn the pin with a zero-value settlement and end the session; and it bounds
///      settlements, not signature validations. See PR #51 and the RHI-5757 design note.
contract NoncePinPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The intent executor whose standalone nonce slot marks an executor settlement
    IStandaloneIntentExecutor public immutable INTENT_EXECUTOR;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param intentExecutor The intent executor to consult for executor-side settlements
    constructor(address intentExecutor) {
        INTENT_EXECUTOR = IStandaloneIntentExecutor(intentExecutor);
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev `configured` is separate so a pinned nonce of zero differs from an unset entry
    struct PinnedNonce {
        bool configured;
        uint256 nonce;
    }

    /// @dev Layout follows the IPolicy recommendation: id => msg.sender => account
    mapping(
        ConfigId id => mapping(address multiplexer => mapping(address account => PinnedNonce))
    ) internal $pinnedNonce;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Thrown when init data is not exactly one 32-byte nonce
    error InvalidInitDataLength(uint256 length);

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicy
    /// @notice Pins the nonce for a configuration, overwriting any existing entry
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

        $pinnedNonce[configId][msg.sender][account] =
            PinnedNonce({ configured: true, nonce: uint256(bytes32(initData[0:32])) });

        emit PolicySet(configId, msg.sender, account);
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNATURE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc I1271Policy
    /// @notice Checks that the claim carries the pinned nonce
    /// @dev Returns false rather than reverting; the surrounding policy list decides the outcome
    /// @return True if the claim's nonce equals the pinned nonce
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
        PinnedNonce storage $pinned = $pinnedNonce[id][msg.sender][account];

        if (!$pinned.configured) return false;
        if (signature.length < Permit2HeaderLib.NONCE_END) return false;

        if (Permit2HeaderLib.nonce(signature) != $pinned.nonce) return false;

        // Refuse once the other settlement family has spent this nonce. Only the executor's
        // slot is readable here: Permit2 burns its own bit before validating, so reading that
        // would reject this very settlement.
        return !INTENT_EXECUTOR.isStandaloneIntentNonceConsumed($pinned.nonce, account);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the pinned nonce for a configuration
    /// @return configured Whether a nonce has been pinned
    /// @return nonce The pinned nonce, meaningless when `configured` is false
    function getPinnedNonce(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (bool configured, uint256 nonce)
    {
        PinnedNonce storage $pinned = $pinnedNonce[id][multiplexer][account];
        return ($pinned.configured, $pinned.nonce);
    }

    /*//////////////////////////////////////////////////////////////
                                 ERC165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC165 interface support
    /// @dev Probed at install time; a wrong id makes the policy uninstallable
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(I1271Policy).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
