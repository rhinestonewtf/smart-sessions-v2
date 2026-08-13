// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Nonce Pin Policy
/// @author Rhinestone
/// @notice Constrains a Permit2 claim to one pre-agreed nonce, so every digest a session can
///         produce competes for a single consumable slot per chain.
/// @dev A 1271 policy is `view` and cannot record that a session was spent, so one-time use has
///      to borrow Permit2's nonce bitmap. The signer picks the nonce, so without pinning it can
///      mint a fresh digest per nonce and spend repeatedly.
/// @dev Register alongside Permit2ClaimPolicy. Alone this proves nothing: it reads a
///      caller-supplied slice, and only the claim policy binds that slice to the digest.
/// @dev Limits, all of them real: the guarantee is per chain, not per session; any whitelisted
///      arbiter can burn the pin with a zero-value settlement and end the session; and it bounds
///      settlements, not signature validations. See PR #51 and the RHI-5757 design note.
contract NoncePinPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Must track `Permit2ClaimPolicy._decodePermit2Header`; drift here is silent
    uint256 internal constant NONCE_START = 20;
    uint256 internal constant NONCE_END = 52;

    /*//////////////////////////////////////////////////////////////
                                IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The Permit2 deployment whose claims this policy constrains
    address public immutable PERMIT2;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param permit2 The Permit2 deployment whose claims this policy constrains
    constructor(address permit2) {
        PERMIT2 = permit2;
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
        address requestSender,
        address account,
        bytes32, /* hash */
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        // The offsets below are the Permit2 layout; another caller means another shape, which
        // these would misread rather than reject. See PR #51 for the claim-list variant.
        if (requestSender != PERMIT2) return false;

        PinnedNonce storage $pinned = $pinnedNonce[id][msg.sender][account];

        if (!$pinned.configured) return false;
        if (signature.length < NONCE_END) return false;

        return uint256(bytes32(signature[NONCE_START:NONCE_END])) == $pinned.nonce;
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
