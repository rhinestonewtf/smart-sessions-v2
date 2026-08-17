// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// forgefmt: disable-start
/// @title Settlement Once Policy
/// @author Rhinestone
/// @notice PROOF OF CONCEPT. One session, two settlement families, one spend - enforced from the
///         ACTION surface for the executor route rather than the 1271 surface.
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │  The 1271 surface is `view`, so a policy there cannot record a spend.   │
/// │  It can only READ consumables the settlement layers burn for it, which  │
/// │  is what forces the pinned-nonce design.                               │
/// │                                                                        │
/// │  The action surface reached through SmartSessionEmissary.verifyExecution│
/// │  is NOT view. A policy there can burn its own flag - so it does not     │
/// │  need to see the executor's nonce at all, only to remember that it ran. │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// @dev Route split. The executor route arrives on `checkAction` (via
///      `StandaloneIntent -> SmartSessionEmissary.verifyExecution -> _enforceActionPolicies`).
///      The Permit2 route - Across and Eco, which share one bitmap - arrives on
///      `check1271SignedAction`. Each closes the other's diagonal:
///
///        executor settles  -> burns $spent[mux][account][N] -> the 1271 side reads it, refuses
///        Permit2  settles  -> burns Permit2's bitmap        -> `checkAction` reads it, refuses
///
///      Uniqueness WITHIN a family is free: Permit2 rejects a second spend of its nonce, and
///      the executor consumes its own nonce before validating. This policy only closes the
///      cross-family cases, exactly as the 1271 multiplexer does.
///
/// @dev The spend record is keyed on the PINNED NONCE, not the ConfigId. That is not a style
///      choice - keying it on ConfigId is silently broken, and was, until an audit caught it.
///      SmartSessions gives each policy SLOT its own ConfigId:
///        action  keccak(account, keccak(permissionId, actionId))
///        1271    keccak(account, keccak("ERC1271: ", permissionId))
///      They can never be equal, so a flag written by one half under its own ConfigId is
///      invisible to the other and the cross-family exclusion silently never fires. The nonce is
///      the only value both surfaces can name identically.
///
/// @dev INSTALL-TIME REQUIREMENT, third, and a direct consequence of the above: the two surfaces
///      are configured by SEPARATE initData blobs, and both must pin the SAME nonce. Neither half
///      can see the other's config, so nothing here can check it. Pin different values and the
///      halves key different records and stop excluding each other - the same silent failure the
///      ConfigId keying had.
///
/// @dev INSTALL-TIME REQUIREMENT, and the sharp edge of this design. Action policies are
///      invoked once per execution in the batch, so this policy MUST be installed on an
///      actionId - a (target, selector) pair - that occurs EXACTLY ONCE per settlement.
///      Install it on one that can occur twice and a legitimate settlement fails on its second
///      occurrence; install it on one a settlement can omit and that settlement is unbounded.
///      Nothing here can verify either property. `ArgPolicy` constrains what the ops may do;
///      this constrains how many times. They are complements, not substitutes.
///
/// @dev INSTALL-TIME REQUIREMENT, second. `checkAction` runs only when the executor dispatches
///      to `verifyExecution`, which happens only for sigMode EMISSARY_EXECUTION and the two
///      hybrids that fall through to it. The sigMode byte lives in the ops the session key
///      signs, so the settler chooses it. On any ERC-1271 mode this policy's action half never
///      runs. That makes the executor-route guarantee conditional on the settler's choice -
///      an operational assumption, not one this contract enforces.
// forgefmt: disable-end
contract SettlementOncePolicy is IActionPolicy, I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when init data is not exactly one 32-byte nonce
    error InvalidInitDataLength(uint256 length);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the executor route consumes the session's single spend
    event ExecutorSettled(ConfigId indexed id, address indexed account);

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @param configured Whether a nonce has been pinned for this configuration
    /// @param nonce The pinned nonce, used for the Permit2 pin and the bitmap lookup
    struct Session {
        bool configured;
        uint256 nonce;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Start of the nonce in a Permit2 claim payload, after the arbiter
    uint256 internal constant PERMIT2_NONCE_START = 20;

    /// @dev Width of the nonce
    uint256 internal constant NONCE_LENGTH = 32;

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The Permit2 deployment whose bitmap records Across and Eco settlements
    ISignatureTransfer public immutable PERMIT2;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev configId => multiplexer => account => session. Holds the PIN only. ConfigId is a
    ///      per-policy-slot identity: SmartSessions derives it as
    ///      `keccak(account, keccak(permissionId, actionId))` for the action surface and
    ///      `keccak(account, keccak("ERC1271: ", permissionId))` for the 1271 surface, so the two
    ///      halves of this policy are ALWAYS handed different values and each gets its own entry.
    ///      That is correct for configuration; it is fatal for shared state.
    mapping(ConfigId => mapping(address => mapping(address => Session))) internal $sessions;

    /// @dev multiplexer => account => nonce => spent. Holds the SPEND.
    ///      Keyed on the pinned nonce rather than the ConfigId, because the nonce is the one
    ///      value both surfaces can name identically: the action half takes it from its own
    ///      config, the 1271 half reads it out of the settlement payload and pins it. Everything
    ///      else in scope differs across the two surfaces or is absent from one of them.
    mapping(address => mapping(address => mapping(uint256 => bool))) internal $spent;

    constructor(ISignatureTransfer permit2) {
        PERMIT2 = permit2;
    }

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Pins the nonce this session may settle on
    /// @param account The account this configuration belongs to
    /// @param configId The configuration being initialized
    /// @param initData A single 32-byte nonce
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        if (initData.length != 32) revert InvalidInitDataLength(initData.length);

        uint256 nonce = uint256(bytes32(initData[0:32]));

        Session storage $session = $sessions[configId][msg.sender][account];
        $session.nonce = nonce;
        $session.configured = true;

        // Re-enabling restores the session's single spend. Note this clears the SHARED record,
        // so installing the second surface of the same session also clears it - which is
        // harmless only because both installs happen before either can settle.
        $spent[msg.sender][account][nonce] = false;
    }

    /*//////////////////////////////////////////////////////////////
                          EXECUTOR ROUTE - ACTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Consumes the session's single spend for the executor route
    /// @dev Not `view`, which is the whole point: this is the only surface on which a session
    ///      policy can record that a settlement happened. The nonce is not reachable from the
    ///      arguments - `checkAction` receives no nonce and no digest - so it is taken from this
    ///      configuration, and it IS load-bearing here: it keys both the Permit2 bitmap read and
    ///      the shared spend record. Install this surface with the same nonce as the 1271 one.
    /// @param id The configuration
    /// @param account The account settling
    /// @return VALIDATION_SUCCESS on the first settlement, VALIDATION_FAILED afterwards
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256,
        bytes calldata
    )
        external
        override
        returns (uint256)
    {
        Session storage $session = $sessions[id][msg.sender][account];

        if (!$session.configured) return VALIDATION_FAILED;

        uint256 nonce = $session.nonce;

        if ($spent[msg.sender][account][nonce]) return VALIDATION_FAILED;
        // EXCLUDE: the Permit2 family settled first, so this route is closed
        if (_permit2Spent(account, nonce)) return VALIDATION_FAILED;

        $spent[msg.sender][account][nonce] = true;
        emit ExecutorSettled(id, account);

        return VALIDATION_SUCCESS;
    }

    /*//////////////////////////////////////////////////////////////
                          PERMIT2 ROUTE - ERC-1271
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates an Across or Eco settlement carries the pinned nonce and that the
    ///         executor route has not already settled
    /// @dev Permit2's own bitmap is deliberately NOT read: Permit2 burns the nonce before it
    ///      validates the signature, so this would reject the settlement in front of it every
    ///      time. Across versus Eco is closed by that same burn, not by this policy.
    /// @param id The configuration
    /// @param account The account settling
    /// @param signature The Permit2 claim payload
    /// @return True if the settlement may proceed
    function check1271SignedAction(
        ConfigId id,
        address,
        address account,
        bytes32,
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        Session storage $session = $sessions[id][msg.sender][account];

        if (!$session.configured) return false;

        // BIND: the settlement must carry the pinned nonce
        if (signature.length < PERMIT2_NONCE_START + NONCE_LENGTH) return false;
        uint256 presented =
            uint256(bytes32(signature[PERMIT2_NONCE_START:PERMIT2_NONCE_START + NONCE_LENGTH]));

        if (presented != $session.nonce) return false;

        // EXCLUDE: the executor family settled first. Read under the nonce just pinned, which is
        // the same key the action half burns under - not this surface's ConfigId, which the
        // action half can never write.
        return !$spent[msg.sender][account][presented];
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Whether the executor route has consumed the spend for a pinned nonce
    function isExecutorSpent(
        address multiplexer,
        address account,
        uint256 nonce
    )
        external
        view
        returns (bool)
    {
        return $spent[multiplexer][account][nonce];
    }

    /// @notice The nonce pinned for this configuration
    function getNonce(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256)
    {
        return $sessions[id][multiplexer][account].nonce;
    }

    /// @notice Whether this configuration is initialized for an account, keyed on the caller
    function isInitialized(address account, ConfigId id) external view returns (bool) {
        return $sessions[id][msg.sender][account].configured;
    }

    /// @notice Whether this configuration is initialized for an account through a multiplexer
    function isInitialized(
        address account,
        address multiplexer,
        ConfigId id
    )
        external
        view
        returns (bool)
    {
        return $sessions[id][multiplexer][account].configured;
    }

    /// @notice ERC-165 support for both surfaces this policy serves
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /*//////////////////////////////////////////////////////////////
                                 INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Reads Permit2's unordered-nonce bitmap for `nonce`
    function _permit2Spent(address account, uint256 nonce) internal view returns (bool) {
        uint256 wordPos = nonce >> 8;
        uint256 bitPos = nonce & 0xff;
        return (PERMIT2.nonceBitmap(account, wordPos) >> bitPos) & 1 == 1;
    }
}
