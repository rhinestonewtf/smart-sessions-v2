// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { OneTimeUseIdStorageLib } from "@policies/onetime/lib/OneTimeUseIdStorageLib.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// forgefmt: disable-start
/// @title One Time Use Id Policy
/// @author Rhinestone
/// @notice Lets one session spend at most once across any number of settlement layers. The session
///         pins an id it invents; a settlement burns that id by calling this contract; every later
///         settlement is refused. The witness the ERC-1271 route reads is the settlement's own
///         Permit2 nonce, used only so the settling check can recognise its own burn - which is why
///         a `Permit2ClaimPolicy` binding that blob to the digest must be installed alongside.
///
/// @dev Trust model. The policy assumes the orchestrator composes the settlement's ops, and makes
///      the exactly-once guarantee against a hostile SUBMITTER, not a hostile ops author. The ops
///      sit inside the signed digest, so a solver can only submit or withhold the settlement. Every
///      unsigned input must fail closed: `preClaimGasStipend` is the low half of `packedGasValues`
///      and never enters `hashMandateRaw`, so a submitter can starve the burn's gas - but a skipped
///      burn leaves no nomination, so the settling check refuses. No burn, no settle. Covered by
///      `GasStarve` and `BurnSkippable`.
///
///      Build requirements the contract cannot check (properties of the signed blob):
///        - the pre-claim carries the `consume`/`consumeFor` call
///        - it carries no other unpoliced executions; the pre-claim's action surface is not
///          dispatched on the ERC-1271 route, so ops there are bounded by the signer
///        - its sigMode is the one the 1271 route expects
///
///      Where the action surface IS dispatched (the executor route), `checkAction` enforces two
///      things on-chain, wherever the once-policy sits in the dispatched action list (including the
///      fallback action):
///        - a `consume` may only name the session's own id, so a session cannot burn another
///          session's id (a permanent cross-session denial of service)
///        - a `consumeFor` is refused. Only the ERC-1271 route nominates, and its action surface is
///          never dispatched here; a `consumeFor` on the executor route would set a nomination a
///          Permit2 settlement that skipped its own burn could ride, breaking exactly-once across
///          layers.
///
/// @dev Read here, burn there. `checkAction` does not write; the burn is `consume`, an execution
///      the settlement carries with the account as msg.sender. A policy that burned during
///      validation would refuse the second covered execution of the settlement it just authorized,
///      and pre-claim ops are routinely more than one execution. Reading during validation and
///      burning during execution means nothing in a batch can observe its own burn.
///
/// @dev The settling ERC-1271 read requires proof of the burn. The Permit2 arbiter route validates
///      ERC-1271 twice in one settlement, with the burn in between, from different callers:
///
///        _permit2PreClaimOps -> executePreClaimOpsWithPermit2Stub
///                                 |- isValidSignature         <- check #1, from the executor
///                                 `- executeOps(preClaimOps)  <- `consumeFor` burns here
///        _unlockPermit2      -> Permit2.permitWitnessTransferFrom
///                                 `- account.isValidSignature <- check #2, from PERMIT2
///
///      Check #1 runs before the burn and its refusal is swallowed by the failure-tolerant arbiter,
///      so it only asks "is this unspent?" - which is what lets the burn happen. Check #2 requires
///      the nomination `consumeFor` recorded to match the settlement in front of it, so a settlement
///      that skipped its burn cannot settle, and a second settlement cannot borrow the first's
///      nomination (its own `consumeFor` clears the nomination once the id is spent). The burn must
///      be durable rather than transient-only because the arbiter swallows pre-claim failures; the
///      refusal that reverts is check #2, inside `permitWitnessTransferFrom`.
///
/// @dev `checkAction` is strict: action policies run during validation, before any execution in the
///      batch, so a settlement never observes its own burn there.
///
/// @dev The record is keyed on (id, account) - not ConfigId or the multiplexer - because `consume`
///      is called by the account, which knows neither, and SmartSessions hands each policy slot its
///      own ConfigId (a flag written under one is invisible to the other).
///
/// @dev Limit: the settling proof exists for the PERMIT2 caller only. Every other ERC-1271 caller
///      takes the advisory "is this unspent?" read, which a settlement can satisfy without burning.
///      Consequences in this repo:
///        - installed in `Session.claimPolicies`, a Compact settlement carrying no `consume` reads
///          unspent and settles repeatedly
///        - a Compact settlement that does burn runs its pre-claim before `verifyClaim`, so the
///          advisory read sees the burn and refuses its own settlement
///      So this policy bounds the Permit2 arbiter route and the executor route, not the Compact
///      claim route. Supporting another layer requires teaching this file which caller settles it
///      and how to prove a burn there.
///
/// @dev Install-time requirement: the 1271 list must also carry a policy that binds the claim blob
///      to the digest (`Permit2ClaimPolicy` is the intended partner). `signature[20:52]` is the
///      settlement's nonce only because that policy recomputes the digest from the same blob and
///      compares it to `hash`. Installed alone, `presented` is caller-chosen and the proof
///      degenerates to "some nomination is live". `minPoliciesToEnforce` is 1, so installing this
///      alone is a legal configuration nothing rejects.
///
/// @dev Install-time requirement: the id must match across surfaces. ConfigId is generated by
///      SmartSessions, and not one per policy list:
///
///        action slot   keccak(account, keccak(permissionId, actionId))     - one PER ACTION
///        1271 list     keccak(account, keccak("ERC1271: ", permissionId))
///        claim list    keccak(account, keccak("ERC1271: ", permissionId))  - the SAME one
///
///      The action halves and the 1271 half get different ConfigIds initialized from different
///      blobs, but the 1271 list and the claim list share a ConfigId (SmartSessionManager
///      `_enablePolicies`, both passing `toErc1271PolicyId().toConfigId`); the claim list is enabled
///      second, so its id overwrites the 1271 one for both surfaces. Every blob must carry the same
///      id - nothing here can check it. Pin different values and the halves key different records,
///      the cross-route exclusion never fires, and both surfaces still report "configured". This is
///      also why one session must cover every settlement layer: separate permissionIds get separate
///      ConfigIds and separate spends, so exactly-once holds per layer instead of across them.
///
/// @dev Install-time requirement: a settlement must carry exactly one `consume`. Two poison the
///      settlement so it refuses itself. Enforceable via `Permit2ClaimPolicy`'s FIELD_ORIGIN_OPS in
///      sub-policy mode, which receives the pre-claim ops hash, so pinning that hash fixes the ops
///      to exactly `[consume(id)]`.
///
/// @dev Install-time requirement: install this on EVERY action the session permits, so any
///      execution the settlement performs reads the record and a settler cannot dodge the check by
///      composing a batch out of some other permitted action.
///
/// @dev Install-time requirement: the injected `consume` must sit inside the signed intent (the
///      pre-claim ops covered by the digest) so that removing it invalidates the signature. Nothing
///      here can check it is present: if a settlement runs with no `consume`, nothing burns and the
///      session is not spent. The guarantee is that a settlement which does burn cannot be followed
///      by another, not that every settlement burns.
///
/// @dev Install-time requirement: the id must be fresh per enable and unique per account across
///      every session using this policy. The record is never cleared, so reusing a burned id yields
///      a session that cannot settle - denial, never a second spend. A random 256-bit value is the
///      intended shape.
// forgefmt: disable-end
contract OneTimeUseIdPolicy is IOneTimeUseIdPolicy, IActionPolicy, I1271Policy {
    /// @dev Start of the nonce in `Permit2ClaimPolicy`'s claim blob, after the arbiter
    uint256 internal constant PERMIT2_NONCE_START = 20;

    /// @dev Width of the nonce
    uint256 internal constant NONCE_LENGTH = 32;

    /// @notice The Permit2 deployment. Used only to tell the settling ERC-1271 check apart from the
    ///         pre-claim one - they arrive from different callers.
    ISignatureTransfer public immutable PERMIT2;

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

        OneTimeUseIdStorageLib.pin(configId, msg.sender, account).id = id;

        // The spend is not cleared here: this runs during an ENABLE-mode settlement, and the record
        // carries no session identity, so clearing would free an unrelated session on the same id.
    }

    /*//////////////////////////////////////////////////////////////
                               THE BURN
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    /// @dev Not idempotent: a second `consume` of a spent id reverts the transaction, which closes
    ///      the same-transaction double-spend. A settlement must carry exactly one `consume`.
    function consume(uint256 id) external override {
        _burn(id, OneTimeUseIdStorageLib.NOT_NOMINATED);
    }

    /// @inheritdoc IOneTimeUseIdPolicy
    function consumeFor(uint256 id, uint256 witness) external override {
        _burn(id, OneTimeUseIdStorageLib.nominationOf(witness));
    }

    /// @dev `nomination` is NOT_NOMINATED for the action route and a settlement-specific value for
    ///      the ERC-1271 route.
    function _burn(uint256 id, uint256 nomination) internal {
        if (OneTimeUseIdStorageLib.spend(id, msg.sender).burned) {
            // Already burned: this call is not the burn, so clear any nomination it left.
            OneTimeUseIdStorageLib.setNomination(
                id, msg.sender, OneTimeUseIdStorageLib.NOT_NOMINATED
            );
            return;
        }

        OneTimeUseIdStorageLib.setNomination(id, msg.sender, nomination);
        OneTimeUseIdStorageLib.spend(id, msg.sender).burned = true;
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
        uint256 pinned = OneTimeUseIdStorageLib.pin(id, msg.sender, account).id;
        if (pinned == 0) return VALIDATION_FAILED;

        if (target == address(this) && data.length >= 4) {
            bytes4 selector = bytes4(data[0:4]);

            // The executor route burns via `consume`, which nominates nothing. `consumeFor`
            // nominates a settlement and is legitimate ONLY on the ERC-1271 route, whose action
            // surface is never dispatched here. A `consumeFor` reaching checkAction is therefore
            // an executor-route op setting a nomination it does not own - which a Permit2
            // settlement that skipped its own burn could then ride, breaking exactly-once across
            // layers. Refuse it outright.
            if (selector == this.consumeFor.selector) return VALIDATION_FAILED;

            // A `consume` may only name the session's OWN id: otherwise a second session on the
            // same account could name this one's id and brick it permanently (a cross-session
            // DoS), while its own id stays clean.
            if (
                selector == this.consume.selector && data.length >= 36
                    && uint256(bytes32(data[4:36])) != pinned
            ) return VALIDATION_FAILED;
        }

        return OneTimeUseIdStorageLib.spend(pinned, account).burned
            ? VALIDATION_FAILED
            : VALIDATION_SUCCESS;
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
        uint256 pinned = OneTimeUseIdStorageLib.pin(id, msg.sender, account).id;
        if (pinned == 0) return false;

        // The pre-claim check runs before the burn, so it can only ask "is this unspent?". Its
        // refusal is swallowed by the arbiter, so nothing here is load-bearing.
        if (requestSender != address(PERMIT2)) {
            return !OneTimeUseIdStorageLib.spend(pinned, account).burned;
        }

        // The SETTLING check, inside `permitWitnessTransferFrom`. This one moves the money and is
        // the only refusal that is not swallowed, so it demands POSITIVE PROOF that the settlement
        // in front of it performed the burn - not merely that nobody has burned yet.
        if (signature.length < PERMIT2_NONCE_START + NONCE_LENGTH) return false;
        uint256 presented =
            uint256(bytes32(signature[PERMIT2_NONCE_START:PERMIT2_NONCE_START + NONCE_LENGTH]));

        return OneTimeUseIdStorageLib.nomination(pinned, account)
            == OneTimeUseIdStorageLib.nominationOf(presented);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    function isConsumed(address account, uint256 id) external view override returns (bool) {
        return OneTimeUseIdStorageLib.spend(id, account).burned;
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
        pinned = OneTimeUseIdStorageLib.pin(id, multiplexer, account).id;
        consumed = pinned != 0 && OneTimeUseIdStorageLib.spend(pinned, account).burned;
    }

    /// @notice ERC-165 for both policy surfaces and the view surface
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IOneTimeUseIdPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
