// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { OneTimeUseIdStorageLib } from "@policies/onetime/lib/OneTimeUseIdStorageLib.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IPermit2IntentExecutor } from "@compact-utils/executor/interfaces/IPermit2Intent.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// forgefmt: disable-start
/// @title One Time Use Id Policy
/// @author Rhinestone
/// @notice Lets one session spend at most once across any number of settlement layers, and only
///         before a pinned deadline. The session pins an id it invents; a settlement burns that id
///         by calling this contract; every later settlement is refused. The witness the ERC-1271
///         route reads is the settlement's own Permit2 nonce, used only so the settling check can
///         recognise its own burn - which is why a `Permit2ClaimPolicy` binding that blob to the
///         digest must be installed alongside.
///
/// @dev The deadline bounds a session that is never used, so an authorization cannot be settled
///      long after it was issued. It is enforced on the two READ surfaces - `checkAction` and
///      `check1271SignedAction` - and deliberately not at the burn sites: `consume`/`consumeFor`
///      are keyed on (id, account) and never see a ConfigId, so they cannot read a deadline that is
///      pinned per configuration. Nothing is lost by that. A burn only marks the id spent; what
///      moves money is the settlement, and both routes are gated by a read. A burn after the
///      deadline therefore buys nothing - the settlement behind it is already refused.
///
///      Zero means "never expires", which is the pre-deadline behaviour of this policy. It is a
///      real configuration, not a default to fall into: a caller that wants an unbounded
///      authorization must pin zero deliberately.
///
/// @dev Trust model. Neither the submitter nor the session's ops author is trusted to burn:
///      - Executor route: `checkAction` refuses every execution the session's own burn did not lead
///        in the same transaction (a transient flag the burn's validation sets), so a batch that
///        never burns cannot settle.
///      - Permit2 route: the settling check refuses an unlock whose own pre-claim did not burn (see
///        below), so a skipped or starved burn cannot settle (`GasStarve`, `BurnSkippable`).
///      What stays signer-bounded is the CONTENT of a pre-claim validated through ERC-1271, which
///      `checkAction` never sees; `Permit2ClaimPolicy`'s FIELD_ORIGIN_OPS (sub-policy mode receives
///      the pre-claim ops hash) is the on-chain way to pin it.
///      - The pre-claim entrypoint is permissionless and names its caller as the arbiter, and a
///        pre-claim validated through `checkAction` never reaches the arbiter pin on the 1271
///        list. So a batch led by `consumeFor` - the Permit2-route burn - may carry nothing but
///        zero-value approvals of PERMIT2: a session key running a pre-claim as its own arbiter
///        can then only burn and approve, and the one Permit2 settlement it nominated is still
///        the only thing that moves. Native wraps and other pre-claim ops must not share a
///        batch with `consumeFor`; behind `consume` (the executor route) the batch is unbounded.
///
///      Where the action surface is dispatched, `checkAction` also enforces that a `consume` or
///      `consumeFor` names the session's own id, so a session cannot burn another session's id (a
///      permanent cross-session denial of service).
///
/// @dev Read here, burn there. The burn is `consume`/`consumeFor`, an execution the settlement
///      carries with the account as msg.sender. `checkAction` writes only the transient
///      burn-approved flag; burning during validation would refuse the rest of the batch it just
///      authorized, because a batch is validated before any of it executes.
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
///      Check #1 runs before the burn, so it cannot demand it: it refuses a spent or expired id, or
///      a nonce the executor has not consumed (the real pre-claim consumes it before validating).
///      Check #2 requires the nomination `consumeFor` recorded to match the settlement in front of
///      it, and the executor to have consumed that nonce - which happens in the order's own
///      pre-claim, in a router-signed fill of the same nonce (whose signer is trusted not to
///      collude), or in a pre-claim the session key ran as its own arbiter, which the
///      `consumeFor` batch bound leaves nothing to carry. So a settlement that skipped its burn cannot settle, and a nomination left by a
///      burn in another settlement cannot carry it. The burn must be durable rather than
///      transient-only because the arbiter swallows pre-claim failures; the refusal that reverts is
///      check #2, inside `permitWitnessTransferFrom`.
///
/// @dev The record is keyed on (id, account) - not ConfigId or the multiplexer - because `consume`
///      is called by the account, which knows neither, and SmartSessions hands each policy slot its
///      own ConfigId (a flag written under one is invisible to the other).
///
/// @dev Limit: this policy proves a burn only for the Permit2 caller. For the executor it can only
///      read "unspent, unexpired, nonce consumed", and it cannot tell a Permit2 pre-claim from any
///      other executor-originated ERC-1271 validation - the digest-binding claim policy on the same
///      list is what refuses the rest. Every other ERC-1271 caller - the Compact claim route
///      included - fails closed. So it bounds the Permit2 arbiter route and the executor route only.
///
/// @dev Install-time requirement: the 1271 list must also carry a policy that binds the claim blob
///      to the digest (`Permit2ClaimPolicy` is the intended partner). `signature[20:52]` is the
///      settlement's nonce only because that policy recomputes the digest from the same blob and
///      compares it to `hash`. Installed alone, `presented` is caller-chosen and the proof
///      degenerates to "some nomination is live". `minPoliciesToEnforce` is 1, so installing this
///      alone is a legal configuration nothing rejects. That policy MUST also pin the arbiter
///      (FIELD_ARBITER): the pre-claim entrypoint is permissionless and puts `msg.sender` in the
///      digest as the arbiter, so without the pin a pre-claim validated through ERC-1271 could
///      name any arbiter and consume nonces at will. The pin does not reach a pre-claim validated
///      through `checkAction`; the `consumeFor` batch bound covers that one.
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
///      id AND the same deadline - nothing here can check either. Pin different ids and the halves
///      key different records, the cross-route exclusion never fires, and both surfaces still
///      report "configured"; pin different deadlines and each surface expires on its own. This is
///      also why one session must cover every settlement layer: separate permissionIds get separate
///      ConfigIds and separate spends, so exactly-once holds per layer instead of across them.
///
/// @dev Install-time requirement: install this on EVERY action the session permits, including an
///      action for the session's own `consume`/`consumeFor`, so every execution reads the record and
///      the burn itself is authorised. Each batch carries exactly one burn, first; a second burn
///      poisons the settlement (`consume` reverts; `consumeFor` clears its nomination).
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

    /// @notice The Permit2 deployment. Identifies the settling ERC-1271 check.
    ISignatureTransfer public immutable PERMIT2;

    /// @notice The IntentExecutor - the only non-Permit2 caller allowed the pre-claim check (#1).
    ///         Every other ERC-1271 caller (e.g. the Compact claim route) is refused, so this
    /// policy bounds only the Permit2 and executor routes.
    address public immutable INTENT_EXECUTOR;

    constructor(ISignatureTransfer permit2, address intentExecutor) {
        if (intentExecutor == address(permit2) || intentExecutor == address(0)) {
            revert InvalidIntentExecutor();
        }
        PERMIT2 = permit2;
        INTENT_EXECUTOR = intentExecutor;
    }

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Pins the id this session may spend, and the deadline it may spend it by
    /// @param account The account this configuration belongs to
    /// @param configId The configuration being initialized
    /// @param initData A 32-byte id followed by a 32-byte deadline (zero = never expires)
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        if (initData.length != 64) revert InvalidInitDataLength(initData.length);

        uint256 id = uint256(bytes32(initData[0:32]));
        if (id == 0) revert InvalidId();

        // Rejected here as well as on the reads: a deadline already past pins a session no
        // settlement could ever use, and failing at install says so while a caller is watching.
        uint256 deadline = uint256(bytes32(initData[32:64]));
        if (OneTimeUseIdStorageLib.isExpired(deadline)) {
            revert DeadlineInPast(deadline, block.timestamp);
        }

        OneTimeUseIdStorageLib.PinStorage storage $pin =
            OneTimeUseIdStorageLib.pin(configId, msg.sender, account);
        $pin.id = id;
        $pin.deadline = deadline;

        // The spend is not cleared here: this runs during an ENABLE-mode settlement, and the record
        // carries no session identity, so clearing would free an unrelated session on the same id.
    }

    /*//////////////////////////////////////////////////////////////
                               THE BURN
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    /// @dev Not idempotent: a second `consume` of a spent id reverts, which enforces "exactly one
    ///      consume per settlement". `consumeFor` (the ERC-1271 route) instead clears its
    /// nomination and returns, because its second call legitimately runs before the settling check.
    function consume(uint256 id) external override {
        if (OneTimeUseIdStorageLib.spendRecord(id, msg.sender).burned) revert AlreadyConsumed(id);
        _burn(id, OneTimeUseIdStorageLib.NOT_NOMINATED);
    }

    /// @inheritdoc IOneTimeUseIdPolicy
    function consumeFor(uint256 id, uint256 witness) external override {
        _burn(id, OneTimeUseIdStorageLib.nominationOf(witness));
    }

    /// @dev `nomination` is NOT_NOMINATED for the action route and a settlement-specific value for
    ///      the ERC-1271 route.
    function _burn(uint256 id, uint256 nomination) internal {
        if (OneTimeUseIdStorageLib.spendRecord(id, msg.sender).burned) {
            // Already burned: this call is not the burn, so clear any nomination it left.
            OneTimeUseIdStorageLib.setNomination(
                id, msg.sender, OneTimeUseIdStorageLib.NOT_NOMINATED
            );
            return;
        }

        OneTimeUseIdStorageLib.setNomination(id, msg.sender, nomination);
        OneTimeUseIdStorageLib.spendRecord(id, msg.sender).burned = true;
        emit IdConsumed(msg.sender, id);
    }

    /*//////////////////////////////////////////////////////////////
                               THE READ
    //////////////////////////////////////////////////////////////*/

    /// @notice Refuses every settlement after the one that burned the id, and every execution the
    ///         session's own burn did not lead in this transaction
    /// @dev Writes only the transient burn-approved flag. See the read-here-burn-there note.
    /// @param configId The configuration
    /// @param account The account settling
    /// @return VALIDATION_SUCCESS while the id is unburned and unexpired and this is the session's
    ///         burn or follows it in the transaction, VALIDATION_FAILED otherwise
    function checkAction(
        ConfigId configId,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        override
        returns (uint256)
    {
        OneTimeUseIdStorageLib.PinStorage storage $pin =
            OneTimeUseIdStorageLib.pin(configId, msg.sender, account);
        uint256 pinned = $pin.id;
        if (pinned == 0) return VALIDATION_FAILED;
        if (OneTimeUseIdStorageLib.isExpired($pin.deadline)) return VALIDATION_FAILED;

        if (OneTimeUseIdStorageLib.spendRecord(pinned, account).burned) return VALIDATION_FAILED;

        uint256 burnKind = OneTimeUseIdStorageLib.BURN_NONE;
        if (target == address(this)) {
            // A self-call with no selector can only revert at execution; fail closed.
            if (data.length < 4) return VALIDATION_FAILED;
            bytes4 selector = bytes4(data[0:4]);

            // A burn must be well-formed and name the session's OWN id, or a second session on
            // the same account could brick this one's id. Both burns take the id first.
            uint256 burnLength;
            if (selector == this.consume.selector) {
                burnLength = 36;
                burnKind = OneTimeUseIdStorageLib.BURN_CONSUME;
            } else if (selector == this.consumeFor.selector) {
                burnLength = 68;
                burnKind = OneTimeUseIdStorageLib.BURN_CONSUME_FOR;
            }
            if (burnLength != 0) {
                if (data.length < burnLength || uint256(bytes32(data[4:36])) != pinned) {
                    return VALIDATION_FAILED;
                }
            }
        }

        // The burn must be the session's first execution in the transaction, so a batch that
        // never burns cannot settle: every other execution needs the burn approved before it.
        if (burnKind != OneTimeUseIdStorageLib.BURN_NONE) {
            OneTimeUseIdStorageLib.approveBurn(msg.sender, pinned, account, burnKind);
            return VALIDATION_SUCCESS;
        }

        uint256 approved = OneTimeUseIdStorageLib.burnApproved(msg.sender, pinned, account);
        if (approved == OneTimeUseIdStorageLib.BURN_NONE) return VALIDATION_FAILED;

        // Behind a `consumeFor` only a Permit2 approval may run. The pre-claim entrypoint is
        // permissionless, so the session key can run a pre-claim as its own arbiter through this
        // surface, nominate the settlement it also signed for the real arbiter, and have both
        // land on one burn (`RideSingleTx`). Nothing here can see the arbiter; bounding the batch
        // to the approval the real pre-claim needs leaves that ride nothing to carry.
        if (approved == OneTimeUseIdStorageLib.BURN_CONSUME_FOR && !_isPermit2Approval(value, data))
        {
            return VALIDATION_FAILED;
        }
        return VALIDATION_SUCCESS;
    }

    /// @dev A zero-value `approve(PERMIT2, amount)` with nothing appended. Approving Permit2
    ///      moves nothing on its own: every Permit2 transfer is still gated by the account's
    ///      signature, which for this session is the settling check.
    function _isPermit2Approval(uint256 value, bytes calldata data) internal view returns (bool) {
        return value == 0 && data.length == 68 && bytes4(data[0:4]) == IERC20.approve.selector
            && uint256(bytes32(data[4:36])) == uint160(address(PERMIT2));
    }

    /// @notice Refuses any ERC-1271 settlement that cannot prove it performed the burn
    /// @dev The settling caller must PROVE it burned; the executor's pre-claim check can only read
    ///      that the id is unspent and its nonce consumed. This surface is `view` and cannot burn.
    /// @param configId The configuration
    /// @param account The account settling
    /// @return True if the settlement may proceed
    function check1271SignedAction(
        ConfigId configId,
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
        OneTimeUseIdStorageLib.PinStorage storage $pin =
            OneTimeUseIdStorageLib.pin(configId, msg.sender, account);
        uint256 pinned = $pin.id;
        if (pinned == 0) return false;

        // Refused for every caller, before the routes diverge: an expired authorization must not
        // settle, and both checks of a Permit2 settlement run in one transaction, so neither route
        // can straddle the deadline.
        if (OneTimeUseIdStorageLib.isExpired($pin.deadline)) return false;

        // Any caller other than Permit2 or the executor (e.g. the Compact claim route) is refused:
        // this policy proves a burn only for Permit2, so it cannot bound those routes.
        if (requestSender != INTENT_EXECUTOR && requestSender != address(PERMIT2)) return false;

        if (signature.length < PERMIT2_NONCE_START + NONCE_LENGTH) return false;
        uint256 presented =
            uint256(bytes32(signature[PERMIT2_NONCE_START:PERMIT2_NONCE_START + NONCE_LENGTH]));

        // The executor consumes the nonce only in the order's own pre-claim (before validating it)
        // or a router-signed fill, so neither check passes for a nonce no such step has used.
        if (!IPermit2IntentExecutor(INTENT_EXECUTOR)
                .isPermit2IntentNonceConsumed(presented, account)) {
            return false;
        }

        // The executor's pre-claim check runs before the burn, so it can only refuse a spent id.
        if (requestSender == INTENT_EXECUTOR) {
            return !OneTimeUseIdStorageLib.spendRecord(pinned, account).burned;
        }

        // The Permit2 settling check, inside `permitWitnessTransferFrom`: the refusal that reverts,
        // so it demands the nomination this settlement's own burn recorded.
        return OneTimeUseIdStorageLib.nomination(pinned, account)
            == OneTimeUseIdStorageLib.nominationOf(presented);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    function isUsed(address account, uint256 id) external view override returns (bool) {
        return OneTimeUseIdStorageLib.spendRecord(id, account).burned;
    }

    /// @notice The id pinned for a configuration, whether it has been spent, and when it expires
    /// @return pinned The pinned id, or zero if this configuration was never initialized
    /// @return consumed Whether that id has been burned
    /// @return deadline The last timestamp a settlement may use it, or zero if it never expires
    function usage(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        override
        returns (uint256 pinned, bool consumed, uint256 deadline)
    {
        OneTimeUseIdStorageLib.PinStorage storage $pin =
            OneTimeUseIdStorageLib.pin(configId, multiplexer, account);
        pinned = $pin.id;
        deadline = $pin.deadline;
        consumed = pinned != 0 && OneTimeUseIdStorageLib.spendRecord(pinned, account).burned;
    }

    /// @notice ERC-165 for both policy surfaces and the view surface
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IOneTimeUseIdPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
