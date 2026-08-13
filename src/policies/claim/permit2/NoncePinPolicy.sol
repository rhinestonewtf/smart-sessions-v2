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
/// @dev The nonce sits at bytes [20:52] of the Permit2 claim payload, after the arbiter.
///      See `Permit2ClaimPolicy._decodePermit2Header` for the full header layout — it is
///      documented there and deliberately not duplicated here, because a second copy is
///      what drifts.
///
/// @dev Register this ALONGSIDE Permit2ClaimPolicy in the ERC-1271 policy list. Policies in
///      that list are ANDed and each receives the identical payload, so this policy rides the
///      claim policy's digest recomputation for authenticity of the slice it reads. On its own
///      it proves nothing — it only constrains a value the claim policy has bound to the digest,
///      and a list holding only this policy still satisfies the one-policy minimum.
///
/// @dev Only answers true when Permit2 itself is the caller. Both the ERC-1271 list and the
///      per-lockTag claim list are enabled with the SAME config id and multiplexer, so the
///      claim list is a supported install site, not a hypothetical slip — and there the payload
///      is the Compact layout, where these offsets would read a domain-separator tail spliced
///      onto a nonce head. That misparse leaves a large family of nonces satisfying one pin
///      while the configuration still reads as correct. Binding to the settlement contract
///      makes every non-Permit2 install fail closed instead of silently mis-parsing.
///
/// @dev Fails CLOSED when unconfigured, unlike the claim policy family, whose empty mode
///      configuration degenerates to "check nothing".
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                       What the pin does NOT give                        │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// @dev Once per CHAIN, not once per session. Permit2 nonce bitmaps live in each chain's
///      deployment, so the same session enabled on N chains permits N settlements of the same
///      pinned nonce. Pin per chain, or state the guarantee per chain.
///
/// @dev Any authorized arbiter can kill the session for free. Permit2 burns the nonce before
///      it transfers, and a zero requested amount skips the transfer entirely — so any one of
///      the whitelisted spenders can consume the pin while moving nothing. Unpinned that wastes
///      one nonce out of many; pinned it ends the session. Pinning buys one-time use and pays
///      for it with this. The same applies to any unrelated Permit2 activity that happens to
///      land on the pinned value, and nothing here enforces that two sessions pick different
///      pins — derive the nonce from something session-unique.
///
/// @dev It bounds SETTLEMENTS, not validations. The consumed bit lives in Permit2's bitmap, and
///      this policy is `view`, so it will answer true for unlimited signature checks. Anything
///      treating a successful ERC-1271 validation as one-shot authorization, without settling
///      through Permit2, gets no protection from the pin.
// forgefmt: disable-end
contract NoncePinPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Start of the nonce in the Permit2 claim payload, after the 20-byte arbiter
    /// @dev Must track `Permit2ClaimPolicy._decodePermit2Header`, which decodes the same
    ///      header. A layout change there is silent here: this policy would keep reading the
    ///      old offsets and return a wrong boolean rather than reverting.
    uint256 internal constant NONCE_START = 20;

    /// @dev End of the nonce in the Permit2 claim payload
    uint256 internal constant NONCE_END = 52;

    /*//////////////////////////////////////////////////////////////
                                IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The Permit2 deployment whose claims this policy constrains
    /// @dev Checked against the ERC-1271 caller, so an install on any other validation path
    ///      fails closed rather than parsing a payload it does not understand
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
    /// @param requestSender The contract that invoked ERC-1271 validation on the account
    /// @param account The account that signed
    /// @param signature The Permit2 claim payload
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
        // Fail closed unless Permit2 is asking. The offsets below are the Permit2 layout, and
        // any other caller - notably the claim path, where TheCompact asks and the payload has
        // a different shape - would have them read the wrong bytes and answer confidently.
        if (requestSender != PERMIT2) return false;

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
    /// @dev Smart sessions probes this at install time and rejects the policy if it returns
    ///      false, so a wrong id here means the policy cannot be installed at all
    /// @param interfaceId The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(I1271Policy).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
