// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

// forgefmt: disable-start
/// @title Nonce Pin Policy
/// @author Rhinestone
/// @notice Constrains a Permit2 claim to a single, pre-agreed nonce, turning Permit2's
///         per-nonce replay protection into per-session one-time use.
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                            Why this exists                              │
/// │                                                                         │
/// │  A 1271 policy is `view` and cannot record that a session was used.     │
/// │  The only on-chain evidence that a Permit2 claim settled is Permit2's   │
/// │  own nonce bitmap, which it consumes per owner.                         │
/// │                                                                         │
/// │  That evidence is only useful if the nonce is fixed in advance. The     │
/// │  session signer chooses the nonce, so without pinning it can mint a     │
/// │  fresh digest per nonce and spend repeatedly, each spend individually   │
/// │  replay-protected but the session unbounded.                            │
/// │                                                                         │
/// │  Pinning collapses every digest the session can produce into competing  │
/// │  for one consumable slot: the first to settle burns it, the rest revert │
/// │  at Permit2 with InvalidNonce.                                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                        Permit2 claim data layout                        │
/// │  ┌───────────┬──────────────────────────────────────────────────────┐   │
/// │  │  [0:20]   │  arbiter (address) - Permit2 spender                  │   │
/// │  │  [20:52]  │  nonce (uint256)                     ← checked here   │   │
/// │  │  [52:84]  │  deadline (uint256)                                   │   │
/// │  │  [84:...] │  tokenIn / mandate                                    │   │
/// │  └───────────┴──────────────────────────────────────────────────────┘   │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// @dev Register this ALONGSIDE Permit2ClaimPolicy in the ERC-1271 policy list. Policies in
///      that list are ANDed and each receives the identical payload, so this policy rides the
///      claim policy's digest recomputation for authenticity of the slice it reads. On its own
///      it proves nothing — it only constrains a value the claim policy has bound to the digest.
///
/// @dev Install in the ERC-1271 policy list, NOT the claim policy list. Permit2 settlement
///      reaches the account through ERC-1271; claim verification is TheCompact's path. A pin
///      installed in the wrong list leaves the Permit2 path unconstrained.
///
/// @dev Fails CLOSED when unconfigured, unlike the claim policy family, whose empty mode
///      configuration degenerates to "check nothing".
// forgefmt: disable-end
contract NoncePinPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Start of the nonce in the Permit2 claim payload, after the 20-byte arbiter
    uint256 internal constant NONCE_START = 20;

    /// @dev End of the nonce in the Permit2 claim payload
    uint256 internal constant NONCE_END = 52;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The nonce pinned for a given configuration
    /// @dev `configured` is tracked separately so that a pinned nonce of zero is
    ///      distinguishable from an uninitialized entry
    struct PinnedNonce {
        bool configured;
        uint256 nonce;
    }

    /// @notice Pinned nonce per configuration, multiplexer and account
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
    /// @notice Pins the nonce for a configuration
    /// @dev Overwrites any existing entry, as required of policies re-initialized without
    ///      being deinitialized first
    /// @param account The account this configuration belongs to
    /// @param configId The configuration ID
    /// @param initData The nonce to pin, encoded as a single 32-byte word
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
    /// @dev Returns false rather than reverting, so the surrounding policy list decides the
    ///      outcome. Fails closed on both an unconfigured entry and a payload too short to
    ///      contain a nonce.
    /// @param id The configuration ID
    /// @param account The account that signed
    /// @param signature The Permit2 claim payload
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

        // Fail closed when this configuration was never initialized
        if (!$pinned.configured) return false;

        // Fail closed when the payload cannot contain a nonce
        if (signature.length < NONCE_END) return false;

        return uint256(bytes32(signature[NONCE_START:NONCE_END])) == $pinned.nonce;
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the pinned nonce for a configuration
    /// @param id The configuration ID
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @param account The account the configuration belongs to
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
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(I1271Policy).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
