// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

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
/// │  Here the marker is OURS, and no nonce is pinned in advance. The ERC-1271│
/// │  route does read ONE caller-supplied field - the settlement's own Permit2│
/// │  nonce, used purely as a witness so the settling check can recognise its │
/// │  own burn. That is the design's one concession, and it costs a           │
/// │  dependency on `Permit2ClaimPolicy` binding that blob to the digest.     │
/// └──────────────────────────────────────────────────────────────────────────┘
///
/// @dev WHO IS TRUSTED. This policy assumes the ORCHESTRATOR composes the settlement's ops. It
///      makes the exactly-once guarantee against a hostile SUBMITTER, not a hostile ops AUTHOR.
///
///      The split follows from what is signed. The ops sit inside the signed digest, so a solver
///      can submit the settlement or withhold it and nothing else. Every unsigned input therefore
///      has to fail closed, and one exists: `preClaimGasStipend` is the low half of
///      `packedGasValues` and never enters `hashMandateRaw`, so the submitter picks the gas budget
///      of a call the user signed. Starving it skips the burn - and a skipped burn leaves no
///      nomination, so check #2 refuses. No burn, no settle. Held by `GasStarve` and
///      `BurnSkippable`.
///
///      What the orchestrator must get right off-chain, because nothing here can check it:
///
///        - the pre-claim carries the `consume`/`consumeFor` call at all
///        - it names THIS account's own id, not another session's - burning a foreign id is a
///          cross-session denial of service
///        - it carries no other unpoliced executions; the pre-claim's action surface is not
///          dispatched on the ERC-1271 route, so ops there are bounded by the signer, not by us
///        - its sigMode is the one the 1271 route expects
///
///      All four are properties of a blob the orchestrator builds and signs. They are build
///      requirements on the intent, not invariants this contract enforces. The executor route is
///      the exception: `checkAction` DOES run there, so the id binding and the `consumeFor` ban
///      are enforced on-chain on that route alone.
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
/// @dev THE SETTLING 1271 READ DEMANDS PROOF, and that is the whole trick.
///
///      The Permit2 arbiter route validates ERC-1271 TWICE in one settlement, with the pre-claim
///      execution - and therefore the burn - in between, and the two arrive from DIFFERENT
///      callers:
///
///        _permit2PreClaimOps -> executePreClaimOpsWithPermit2Stub
///                                 |- isValidSignature         <- check #1, from the executor
///                                 `- executeOps(preClaimOps)  <- `consumeFor` burns here
///        _unlockPermit2      -> Permit2.permitWitnessTransferFrom
///                                 `- account.isValidSignature <- check #2, from PERMIT2
///
///      Only check #2 blocks anything: a refusal at check #1 is swallowed by the failure-tolerant
///      arbiter, so nothing enforced there is load-bearing. Check #1 therefore only asks "is this
///      unspent?", which is what lets the burn happen at all.
///
///      Check #2 asks the opposite question. Not "has anyone burned this?" - which passes when
///      nobody has, so a settlement that SKIPPED its burn looks exactly like the first settlement
///      ever, forever - but "can you prove YOU burned it?". `consumeFor` records a nomination
///      naming its own settlement; check #2 requires that nomination to match the settlement in
///      front of it. Skipping the burn therefore means not settling.
///
///      A second settlement cannot borrow the first's nomination, because it cannot name it - and
///      its own `consumeFor` clears the nomination rather than re-issuing it, since an id already
///      spent means the caller is not the burn.
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
/// @dev LIMIT, and the sharpest one. The settling proof exists for the PERMIT2 caller only.
///      Every other ERC-1271 caller takes the advisory read - "is this unspent?" - which is the
///      permissive default a settlement can satisfy without burning anything. Two consequences,
///      both real in this repo:
///
///        - installed in `Session.claimPolicies`, a Compact settlement carrying no `consume`
///          reads unspent and settles, repeatedly
///        - a Compact settlement that DOES burn runs its pre-claim before `verifyClaim`, so the
///          advisory read sees the burn and refuses ITS OWN settlement
///
///      So this policy currently bounds the Permit2 arbiter route and the executor route, and
///      NOT the Compact claim route. Supporting another layer means teaching this file which
///      caller settles it and how to prove a burn there - it is not layer-agnostic, whatever the
///      shape of the marker suggests.
///
/// @dev INSTALL-TIME REQUIREMENT: the 1271 list must also carry a policy that binds the claim
///      blob to the digest - `Permit2ClaimPolicy` is the intended partner. `signature[20:52]` is
///      the settlement's nonce only because that policy recomputes the digest from the same blob
///      and compares it to `hash`. Installed alone, `presented` is caller-chosen and the proof
///      degenerates to "some nomination is live", which proves nothing. `minPoliciesToEnforce`
///      is 1, so installing this alone is a legal configuration that nothing rejects.
///
/// @dev INSTALL-TIME REQUIREMENT, and the one @zeroknots asked about. ConfigId is generated BY
///      SmartSessions, and NOT one per policy list:
///
///        action slot   keccak(account, keccak(permissionId, actionId))     - one PER ACTION
///        1271 list     keccak(account, keccak("ERC1271: ", permissionId))
///        claim list    keccak(account, keccak("ERC1271: ", permissionId))  - the SAME one
///
///      So the action halves and the 1271 half are handed different ConfigIds and are initialized
///      from different blobs - but the 1271 list and the claim list SHARE a ConfigId
///      (SmartSessionManager `_enablePolicies`, both passing `toErc1271PolicyId().toConfigId`).
///      Installing this policy on both with different ids does not key two records: the claim
///      list is enabled SECOND, so its id silently overwrites the 1271 one for both surfaces.
///
///      Every one of those blobs must carry the SAME id. Nothing here can check it: no slot can
///      see another's config. Pin different values and the halves key different records, the
///      cross-route exclusion silently never fires, and both surfaces still report "configured".
///
///      This is also why ONE session must cover every settlement layer. Give each layer its own
///      permissionId and each gets its own ConfigIds AND its own spend - exactly-once then holds
///      per layer instead of across them, which is the opposite of the point.
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
    /// @dev Holds the PIN. Zero means "not configured" - `initializeWithMultiplexer` rejects a
    ///      zero id precisely so one slot can carry both facts. A `bool configured` beside the id
    ///      would not pack with it, so every read cost two SLOADs of two different slots.
    mapping(
        ConfigId configId => mapping(address multiplexer => mapping(address account => uint256 id))
    ) internal $pinnedId;

    /// @dev Start of the nonce in `Permit2ClaimPolicy`'s claim blob, after the arbiter
    uint256 internal constant PERMIT2_NONCE_START = 20;

    /// @dev Width of the nonce
    uint256 internal constant NONCE_LENGTH = 32;

    /// @notice The Permit2 deployment. Used ONLY to tell the settling ERC-1271 check apart from
    ///         the pre-claim one - they arrive from different callers.
    ISignatureTransfer public immutable PERMIT2;

    /// @dev Holds the SPEND. Separate from `$configs` because it has to be reachable from
    ///      `consume`, which is called BY THE ACCOUNT and therefore knows only `(account, id)` -
    ///      never the ConfigId. Keying the spend under a ConfigId would make it invisible to the
    ///      burn site, and invisible across surfaces too: SmartSessions derives a different
    ///      ConfigId per policy slot, so the action half and the 1271 half never share one.
    ///
    ///      The account is the INNER key deliberately. ERC-7562 counts a slot as associated
    ///      storage of the sender only when the final keccak preimage begins with the account, and
    ///      `checkAction` reads this during the 4337 validation phase - account-first nesting
    ///      yields `keccak(id . keccak(account . p))`, which a compliant bundler rejects.
    mapping(uint256 id => mapping(address account => bool burned)) internal $used;

    constructor(ISignatureTransfer permit2) {
        PERMIT2 = permit2;
    }

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

        $pinnedId[configId][msg.sender][account] = id;

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
        _burn(id, NOT_NOMINATED);
    }

    /// @inheritdoc IOneTimeUseIdPolicy
    function consumeFor(uint256 id, uint256 witness) external override {
        _burn(id, _nominationOf(witness));
    }

    /// @dev One burn, one nomination slot. `nomination` is NOT_NOMINATED for the action route,
    ///      which needs none, and a settlement-specific value for the ERC-1271 route.
    function _burn(uint256 id, uint256 nomination) internal {
        bytes32 slot = _txSlot(msg.sender, id);

        if ($used[id][msg.sender]) {
            // Already burned, so this call is not the burn. Clear the nomination rather than
            // re-issuing it - nothing may ride a burn it did not perform.
            _setNomination(slot, NOT_NOMINATED);
            return;
        }

        _setNomination(slot, nomination);
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
        uint256 pinned = $pinnedId[id][msg.sender][account];
        if (pinned == 0) return VALIDATION_FAILED;

        // A session permitted to call `consume` may only burn its OWN id. The argument was
        // otherwise unconstrained: a session holder passes ANOTHER session's id and kills it
        // permanently and for free, while its own id stays clean.
        if (target == address(this) && data.length >= 4) {
            bytes4 selector = bytes4(data[0:4]);

            // `consumeFor` NOMINATES a settlement, and this surface cannot tell a legitimate
            // nomination from a forged one - the witness names a settlement it does not own. An
            // executor settlement could otherwise nominate a Permit2 nonce and let a settlement
            // that never burned ride it. Only the ERC-1271 route, which is not gated here, may
            // nominate.
            if (selector == this.consumeFor.selector) return VALIDATION_FAILED;

            // And a session may only ever burn its OWN id
            if (
                selector == this.consume.selector && data.length >= 36
                    && uint256(bytes32(data[4:36])) != pinned
            ) return VALIDATION_FAILED;
        }

        return $used[pinned][account] ? VALIDATION_FAILED : VALIDATION_SUCCESS;
    }

    /// @notice Refuses any ERC-1271 settlement that cannot prove it performed the burn
    /// @dev The settling caller must PROVE it burned; every other caller gets the advisory read.
    ///      This surface is `view` and cannot burn - the record is written by `consumeFor`.
    /// @param id The configuration
    /// @param account The account settling
    /// @return True if the settlement may proceed
    function check1271SignedAction(
        ConfigId id,
        address requestSender,
        address account,
        bytes32,
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        uint256 pinned = $pinnedId[id][msg.sender][account];
        if (pinned == 0) return false;

        // The PRE-CLAIM check, which runs BEFORE the burn and so cannot demand proof of it. It
        // is also the check whose refusal the arbiter swallows, so nothing here is load-bearing;
        // allowing it while unspent is what lets the burn happen at all.
        if (requestSender != address(PERMIT2)) return !$used[pinned][account];

        // The SETTLING check, inside `permitWitnessTransferFrom`. This one moves the money and is
        // the only refusal that is not swallowed, so it demands POSITIVE PROOF that the settlement
        // in front of it performed the burn - rather than merely that nobody has burned yet.
        //
        // That inversion is the whole fix. Under the old default a settlement that skipped its
        // burn was indistinguishable from the first settlement ever, so skipping was free. Now
        // skipping the burn means not settling.
        if (signature.length < PERMIT2_NONCE_START + NONCE_LENGTH) return false;
        uint256 presented =
            uint256(bytes32(signature[PERMIT2_NONCE_START:PERMIT2_NONCE_START + NONCE_LENGTH]));

        return _nomination(_txSlot(account, pinned)) == _nominationOf(presented);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    function isConsumed(address account, uint256 id) external view override returns (bool) {
        return $used[id][account];
    }

    /// @notice The id pinned for a configuration, and whether it has been spent
    /// @return pinned The pinned id, or zero if this configuration was never initialized
    /// @return consumed Whether that id has been burned
    function usage(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256 pinned, bool consumed)
    {
        pinned = $pinnedId[id][multiplexer][account];
        consumed = pinned != 0 && $used[pinned][account];
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
    /// @dev No settlement has been nominated in this transaction
    uint256 internal constant NOT_NOMINATED = 0;

    /// @dev Hashed so that NO witness value collides with NOT_NOMINATED - Permit2 does not
    ///      reserve nonce zero, and neither end of the uint256 range may be unspendable.
    function _nominationOf(uint256 witness) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(witness)));
    }

    function _setNomination(bytes32 slot, uint256 nomination) internal {
        assembly ("memory-safe") {
            tstore(slot, nomination)
        }
    }

    function _nomination(bytes32 slot) internal view returns (uint256 nomination) {
        assembly ("memory-safe") {
            nomination := tload(slot)
        }
    }

    function _txSlot(address account, uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, id));
    }
}
