// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
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
/// @dev THE 1271 READ IS SAME-TRANSACTION TOLERANT, and that is the whole trick.
///
///      The Permit2 arbiter route validates ERC-1271 TWICE in one settlement, with the pre-claim
///      execution - and therefore the burn - in between:
///
///        _permit2PreClaimOps -> executePreClaimOpsWithPermit2Stub
///                                 |- isValidSignature         <- 1271 check #1, nothing burned
///                                 `- executeOps(preClaimOps)  <- `consume` burns here
///        _unlockPermit2      -> Permit2.permitWitnessTransferFrom
///                                 `- account.isValidSignature <- 1271 check #2, sees the burn
///
///      A strict read refuses check #2 and so refuses its own settlement. But a bare "something
///      burned in this transaction" flag is far too generous: a SECOND settlement riding in the
///      same transaction reads it as its own and spends again, because check #2 of settlement one
///      and check #1 of settlement two present the identical state. That was a real double-spend,
///      demonstrated end to end - two Permit2 settlements on distinct nonces, one transaction.
///
///      The read cannot tell them apart, and being `view` it cannot consume a credit either. So
///      the discrimination is done by the WRITE side, which is not view and can see that it is
///      not the burn:
///
///        UNTOUCHED -> BURNING     first `consume`: this transaction performed the burn
///        anything  -> POISONED    a later `consume` on an id already spent, so the caller is
///                                 NOT the burning settlement - refuse everything afterwards
///
///      Only BURNING is tolerated. A second settlement's own injected `consume` is what poisons
///      the transaction against it, which is why the fix needs no partner policy and no knowledge
///      of any settlement layer.
///
///      This is also why the burn must be durable rather than transient-only. The arbiter route
///      swallows pre-claim failures on purpose (PreClaimExecution is failure-tolerant so a failed
///      pre-claim cannot void a claim and strand a solver), so a refusal raised there is ignored -
///      verified by experiment, not assumed. The refusal that MATTERS is check #2, inside
///      `permitWitnessTransferFrom`, which reverts. Narrowing the tolerance by caller does NOT
///      work for the same reason: it only closes the advisory gate.
///
/// @dev `checkAction` is strict - no tolerance at all. Action policies run during validation,
///      before any execution in the batch, so a settlement can never observe its own burn there.
///
/// @dev THE RECORD IS KEYED ON (id, account) - not ConfigId, not the multiplexer. That is forced:
///      `consume` is called by the account, which knows neither. It is also the keying the
///      predecessor had to be corrected into, since SmartSessions hands each policy SLOT its own
///      ConfigId and a flag written under one is invisible to the other.
///
/// @dev INSTALL-TIME REQUIREMENT: a settlement must carry EXACTLY ONE `consume`. Two of them
///      poison the settlement that carries them, so it refuses itself. This is enforceable rather
///      than hopeful: `Permit2ClaimPolicy`'s FIELD_ORIGIN_OPS in sub-policy mode receives the
///      pre-claim ops hash, so pinning that hash fixes the ops to exactly `[consume(id)]`.
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
contract OneTimeUseIdPolicy is IOneTimeUseIdPolicy, IActionPolicy, I1271Policy {
    /// @param configured Whether an id has been pinned for this configuration
    /// @param id The pinned id, the key the burn site and the read site agree on
    struct Config {
        bool configured;
        uint256 id;
    }

    /// @dev configId => multiplexer => account => config. Holds the PIN only.
    mapping(ConfigId => mapping(address => mapping(address => Config))) internal $configs;

    /// @dev id => account => burned. Holds the SPEND, reachable from `consume`, which knows only
    ///      the account and the id.
    ///
    ///      The account is the INNER key deliberately. ERC-7562 counts a slot as associated
    ///      storage of the sender only when the final keccak preimage begins with the account, and
    ///      `checkAction` reads this during the 4337 validation phase - account-first nesting
    ///      yields `keccak(id . keccak(account . p))`, which a compliant bundler rejects.
    mapping(uint256 => mapping(address => bool)) internal $used;

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
    /// @dev NOT idempotent, deliberately. A second `consume` of an already-spent id POISONS the
    ///      transaction, because the only honest reading of it is "a settlement other than the
    ///      burning one is running". That is what closes the same-transaction double-spend, and it
    ///      is why a settlement must carry EXACTLY ONE `consume` - see the install requirements.
    function consume(uint256 id) external override {
        if ($used[id][msg.sender]) {
            // Already burned — either by an earlier settlement in THIS transaction, or in a past
            // one. Either way this call is not the burn, so poison the transaction rather than
            // vouching for it.
            _setTxState(msg.sender, id, POISONED);
            return;
        }

        _setTxState(msg.sender, id, BURNING);
        $used[id][msg.sender] = true;
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
        address target,
        uint256,
        bytes calldata data
    )
        external
        override
        returns (uint256)
    {
        Config storage $config = $configs[id][msg.sender][account];
        if (!$config.configured) return VALIDATION_FAILED;

        uint256 pinned = $config.id;

        // A session permitted to call `consume` may only burn its OWN id. The argument was
        // otherwise unconstrained: a session holder passes ANOTHER session's id and kills it
        // permanently and for free, while its own id stays clean.
        if (
            target == address(this) && data.length >= 36
                && bytes4(data[0:4]) == this.consume.selector
                && uint256(bytes32(data[4:36])) != pinned
        ) return VALIDATION_FAILED;

        return $used[pinned][account] ? VALIDATION_FAILED : VALIDATION_SUCCESS;
    }

    /// @notice Refuses an ERC-1271 settlement once the id was burned by an EARLIER transaction
    /// @dev Tolerates a burn from the transaction currently running - see the contract note. This
    ///      surface is `view` and cannot burn; the durable record is written by `consume`.
    /// @param id The configuration
    /// @param account The account settling
    /// @return True if the settlement may proceed
    function check1271SignedAction(
        ConfigId id,
        address,
        address account,
        bytes32,
        bytes calldata
    )
        external
        view
        override
        returns (bool)
    {
        Config storage $config = $configs[id][msg.sender][account];
        if (!$config.configured) return false;

        uint256 pinned = $config.id;

        return !$used[pinned][account] || _txState(account, pinned) == BURNING;
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    function isConsumed(address account, uint256 id) external view override returns (bool) {
        return $used[id][account];
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

    /// @notice ERC-165 for both policy surfaces and the view surface
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IOneTimeUseIdPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /*//////////////////////////////////////////////////////////////
                                 INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Marks the id as burned by the transaction currently running. Cleared by the EVM at
    ///      the end of it, which is precisely the lifetime the 1271 tolerance needs.
    /// @dev No burn has happened in this transaction
    uint256 internal constant UNTOUCHED = 0;
    /// @dev THIS transaction performed the burn — the one settlement allowed to be tolerated
    uint256 internal constant BURNING = 1;
    /// @dev A second consume was seen, so some settlement other than the burning one is running
    uint256 internal constant POISONED = 2;

    function _setTxState(address account, uint256 id, uint256 state) internal {
        bytes32 slot = _txSlot(account, id);
        assembly ("memory-safe") {
            tstore(slot, state)
        }
    }

    function _txState(address account, uint256 id) internal view returns (uint256 state) {
        bytes32 slot = _txSlot(account, id);
        assembly ("memory-safe") {
            state := tload(slot)
        }
    }

    function _txSlot(address account, uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, id));
    }
}
