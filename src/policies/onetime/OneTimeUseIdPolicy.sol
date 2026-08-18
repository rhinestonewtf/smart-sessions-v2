// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// forgefmt: disable-start
/// @title One Time Use Id Policy
/// @author Rhinestone
/// @notice One session, any number of settlement layers, one spend - while knowing nothing about
///         any of them. The session pins an ID it invents; the settlement burns that id by
///         CALLING this contract; the action surface refuses every later settlement.
///
/// ┌──────────────────────────────────────────────────────────────────────────┐
/// │  The predecessors pinned a NONCE and read the layers' own consumables -  │
/// │  Permit2's bitmap, the executor's three namespaces. That forced this     │
/// │  contract to know each layer's payload layout, to parse a caller-        │
/// │  supplied blob at a fixed byte offset, and to pin a value the            │
/// │  orchestrator only mints days later.                                     │
/// │                                                                          │
/// │  Here the marker is OURS. Nothing caller-supplied is parsed, no layer is │
/// │  named, and adding a settlement layer needs no change to this file.      │
/// └──────────────────────────────────────────────────────────────────────────┘
///
/// @dev READ HERE, BURN THERE. `checkAction` does not write. The burn is `consume`, an execution
///      the settlement carries, with the ACCOUNT as msg.sender.
///
///      The split is forced by batch size. Action policies run once per execution, so a policy
///      that burned during validation would refuse the SECOND covered execution of the very
///      settlement it just authorized. Pre-claim ops are routinely more than one execution, so
///      that is a live failure, not a corner case. Reading during validation and burning during
///      execution removes the question: nothing in a batch can observe its own burn.
///
/// @dev THIS IS NOT AN `I1271Policy`, and that is deliberate rather than an omission.
///
///      The Permit2 arbiter route validates ERC-1271 TWICE in one settlement, with the pre-claim
///      execution in between:
///
///        _permit2PreClaimOps -> executePreClaimOpsWithPermit2Stub
///                                 |- isValidSignature        <- 1271 check #1
///                                 `- executeOps(preClaimOps) <- `consume` burns here
///        _unlockPermit2      -> Permit2.permitWitnessTransferFrom
///                                 `- account.isValidSignature <- 1271 check #2, sees the burn
///
///      A policy on that surface would refuse check #2 and so refuse its own settlement. Not
///      implementing the interface makes that configuration unrepresentable instead of leaving it
///      as a warning nobody reads.
///
///      The route is still bounded, because the pre-claim validation reaches the ACTION surface:
///      settlement one reads a clean record and burns, settlement two reads the burn and fails.
///
/// @dev THE RECORD IS KEYED ON (account, id) - not ConfigId, not the multiplexer. That is forced:
///      `consume` is called by the account, which knows neither. It is also the keying the
///      predecessor had to be corrected into, since SmartSessions hands each policy SLOT its own
///      ConfigId and a flag written under one is invisible to the other.
///
/// @dev INSTALL-TIME REQUIREMENT, and the load-bearing one. Install this on EVERY action the
///      session permits. Any execution the settlement performs then reads the record, so a
///      settler cannot dodge the check by composing a batch out of some other permitted action.
///      Installing it on one action only bounds settlements that happen to use that action.
///
/// @dev INSTALL-TIME REQUIREMENT: the injected `consume` must sit inside the SIGNED intent - in
///      the pre-claim ops covered by the digest - so that removing it invalidates the signature.
///      Nothing in this contract can check that it is present. If a settlement runs with no
///      `consume` in it, nothing burns and the session is not spent; the guarantee is that a
///      settlement which DOES burn cannot be followed by another, not that every settlement
///      burns.
///
/// @dev INSTALL-TIME REQUIREMENT: the id must be fresh per enable and unique per account across
///      every session using this policy. The record is never cleared, so reusing a burned id
///      yields a session that cannot settle - denial, never a second spend. A random 256-bit
///      value is the intended shape; the small integers in the tests are for readability.
// forgefmt: disable-end
contract OneTimeUseIdPolicy is IOneTimeUseIdPolicy, IActionPolicy {
    /// @param configured Whether an id has been pinned for this configuration
    /// @param id The pinned id, the key the burn site and the read site agree on
    struct Config {
        bool configured;
        uint256 id;
    }

    /// @dev configId => multiplexer => account => config. Holds the PIN only.
    mapping(ConfigId => mapping(address => mapping(address => Config))) internal $configs;

    /// @dev account => id => burned. Holds the SPEND, reachable from `consume`, which knows only
    ///      the account and the id.
    mapping(address => mapping(uint256 => bool)) internal $used;

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Pins the id this session may spend
    /// @param account The account this configuration belongs to
    /// @param configId The configuration being initialized
    /// @param initData A single 32-byte id
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        if (initData.length != 32) revert InvalidInitDataLength(initData.length);

        uint256 id = uint256(bytes32(initData[0:32]));
        if (id == 0) revert InvalidId();

        Config storage $config = $configs[configId][msg.sender][account];
        $config.id = id;
        $config.configured = true;

        // The spend is deliberately NOT cleared. `initializeWithMultiplexer` runs DURING a
        // settlement in ENABLE mode, so clearing here hands every ENABLE-mode settlement a fresh
        // spend; and the record carries no session identity, so it would clear an unrelated
        // session pinned to the same id.
    }

    /*//////////////////////////////////////////////////////////////
                               THE BURN
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    /// @dev Idempotent. A settlement may legitimately carry more than one `consume`, and a
    ///      revert-on-already-burned would fail the settlement it is meant to mark.
    function consume(uint256 id) external override {
        if ($used[msg.sender][id]) return;

        $used[msg.sender][id] = true;
        emit IdConsumed(msg.sender, id);
    }

    /*//////////////////////////////////////////////////////////////
                               THE READ
    //////////////////////////////////////////////////////////////*/

    /// @notice Refuses every settlement after the one that burned the id
    /// @dev Does not write. See the read-here-burn-there note on the contract.
    /// @param id The configuration
    /// @param account The account settling
    /// @return VALIDATION_SUCCESS while the id is unburned, VALIDATION_FAILED afterwards
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
        Config storage $config = $configs[id][msg.sender][account];
        if (!$config.configured) return VALIDATION_FAILED;

        return $used[account][$config.id] ? VALIDATION_FAILED : VALIDATION_SUCCESS;
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    function isConsumed(address account, uint256 id) external view override returns (bool) {
        return $used[account][id];
    }

    /// @notice The id pinned for this configuration
    function getId(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256)
    {
        return $configs[id][multiplexer][account].id;
    }

    /// @notice Whether this configuration is initialized for an account, keyed on the caller
    function isInitialized(address account, ConfigId id) external view returns (bool) {
        return $configs[id][msg.sender][account].configured;
    }

    /// @notice ERC-165. Deliberately does NOT advertise `I1271Policy` - see the contract note.
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(IOneTimeUseIdPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
