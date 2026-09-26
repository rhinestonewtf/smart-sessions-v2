// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { OneTimeUseIdStorageLib } from "@policies/onetime/lib/OneTimeUseIdStorageLib.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IPermit2IntentExecutor } from "@compact-utils/executor/interfaces/IPermit2Intent.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// forgefmt: disable-start
/// @title One Time Use Id Policy
/// @author Rhinestone
/// @notice Lets one session run executions in at most ONE transaction, unlocking at most one
///         Permit2 order in it, and only before a pinned deadline. The session pins an id it
///         invents; the first batch it runs leads with a burn of that id (`consume` or
///         `consumeFor`); the burn happens when `checkAction` VALIDATES that op, not when it
///         executes. Every later transaction is refused.
///
/// @dev Burn at validation. `checkAction` runs before any op executes, so it cannot be skipped,
///      starved or swallowed the way an execution can: a pre-claim the arbiter runs
///      failure-tolerantly still burns, even if its executions revert. On validating the session's
///      own well-formed burn it writes the durable spend, marks the transaction as the burning
///      one (transient), and for `consumeFor` records the nomination (transient). Every other op
///      is validated only while that marker is set. A second burn in the same transaction is
///      refused (the spend is already set), so at most one nomination - at most one Permit2
///      unlock - exists per transaction. The executed `consume`/`consumeFor` write nothing; they
///      only check that their own validation happened, so a burn op that never passed
///      `checkAction` (a direct call, a 1271-validated batch) reverts instead of executing.
///
/// @dev What this bounds, and what it does not. The session's OWN action policies still gate
///      every op of every batch: the marker admits an op to the batch, it does not widen what the
///      op may be. Several batches in the burning transaction - own-arbiter pre-claims through the
///      permissionless executor entrypoints, executor-route batches, a fill - are therefore no
///      more than one larger batch would have been. Cumulative policies count across them as
///      they would within one. The one thing this policy does not bound is a 1271-validated
///      batch's CONTENT (`checkAction` never sees it); it refuses every executor-originated 1271
///      validation instead, so such a batch cannot run under a session carrying this policy.
///
/// @dev Multiplexer keying. `checkAction` and `initializeWithMultiplexer` are permissionless, so
///      anyone can pin the account's id under their own address and "burn" it there. The spend,
///      the marker and the nomination are keyed by the multiplexer (msg.sender), and the settling
///      check reads under ITS msg.sender - the same SmartSessionEmissary that validated the burn -
///      so a foreign multiplexer's burn changes nothing for the real one.
///
/// @dev The Permit2 route. The pre-claim must be validated through `verifyExecution` (an
///      execution-emissary sigMode) so its `consumeFor(id, nonce)` reaches `checkAction`; that
///      validation burns and nominates the order. The unlock then validates ERC-1271 from Permit2:
///
///        _permit2PreClaimOps -> executePreClaimOpsWithPermit2Stub
///                                 |- verifyExecution -> checkAction(consumeFor) <- BURN + nominate
///                                 `- executeOps(preClaimOps)                    <- consumeFor: check only
///        _unlockPermit2      -> Permit2.permitWitnessTransferFrom
///                                 `- account.isValidSignature -> check1271SignedAction (settling)
///
///      The settling check requires the nomination to name the nonce in the claim blob AND the
///      executor to have consumed that nonce. Only a pre-claim that passed validation consumes it,
///      and that pre-claim is the burn. A `Permit2ClaimPolicy` binding the blob to the digest must
///      be installed alongside, or `signature[20:52]` is caller-chosen; it must also pin the
///      arbiter (FIELD_ARBITER) for the 1271-validated legs of hybrid sigModes.
///
/// @dev Install-time requirements. Install on EVERY action the session permits, including an
///      action for the session's own `consume`/`consumeFor`. Every blob (action slots and the 1271
///      list) must carry the same id and deadline: SmartSessions gives each slot its own ConfigId
///      and nothing here can cross-check. One session must cover every settlement layer. The id
///      must be fresh per enable and unique per account: the spend is never cleared, so a reused
///      id yields a session that cannot settle - denial, never a second spend. The burn leads the
///      first batch of the transaction and appears exactly once per chain.
// forgefmt: disable-end
contract OneTimeUseIdPolicy is IOneTimeUseIdPolicy, IActionPolicy, I1271Policy {
    /// @dev Start of the nonce in `Permit2ClaimPolicy`'s claim blob, after the arbiter
    uint256 internal constant PERMIT2_NONCE_START = 20;

    /// @dev Width of the nonce
    uint256 internal constant NONCE_LENGTH = 32;

    /// @notice The Permit2 deployment: the only ERC-1271 caller this policy answers
    ISignatureTransfer public immutable PERMIT2;

    /// @notice The IntentExecutor whose Permit2 nonce ledger the settling check consults
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

    /// @notice Pins the id this session may spend and the deadline it may spend it by
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
                             THE BURN OPS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    /// @dev Writes nothing. The burn happened in `checkAction`; this only refuses to execute a
    ///      burn op that validation never saw.
    function consume(uint256 id) external override {
        _requireValidated(id);
    }

    /// @inheritdoc IOneTimeUseIdPolicy
    function consumeFor(uint256 id, uint256) external override {
        _requireValidated(id);
    }

    function _requireValidated(uint256 id) internal view {
        if (!OneTimeUseIdStorageLib.validated(msg.sender, id)) revert BurnNotValidated(id);
    }

    /*//////////////////////////////////////////////////////////////
                               THE READ
    //////////////////////////////////////////////////////////////*/

    /// @notice Burns the session's id when validating its own burn op; admits every other op only
    ///         while this transaction is the one that burned
    /// @param configId The configuration
    /// @param account The account settling
    /// @return VALIDATION_SUCCESS for the session's first well-formed burn of an unspent,
    ///         unexpired id and for every op validated after it in the same transaction,
    ///         VALIDATION_FAILED otherwise
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
                if (
                    value != 0 || data.length < burnLength || uint256(bytes32(data[4:36])) != pinned
                ) {
                    return VALIDATION_FAILED;
                }
            }
        }

        if (burnKind != OneTimeUseIdStorageLib.BURN_NONE) {
            // The burn. Exactly one per (multiplexer, account, id), ever: a spent id refuses a
            // second burn in this transaction as in every later one.
            OneTimeUseIdStorageLib.SpendStorage storage $spend =
                OneTimeUseIdStorageLib.spendRecord(msg.sender, account, pinned);
            if ($spend.burned) return VALIDATION_FAILED;
            $spend.burned = true;

            OneTimeUseIdStorageLib.setBurnedInTx(msg.sender, account, pinned, burnKind);
            OneTimeUseIdStorageLib.setValidated(account, pinned);
            if (burnKind == OneTimeUseIdStorageLib.BURN_CONSUME_FOR) {
                OneTimeUseIdStorageLib.setNomination(
                    msg.sender,
                    account,
                    pinned,
                    OneTimeUseIdStorageLib.nominationOf(uint256(bytes32(data[36:68])))
                );
            }
            emit IdConsumed(account, pinned);
            return VALIDATION_SUCCESS;
        }

        // Every other op rides the burn validated earlier in this transaction. With no marker
        // the batch never burned, or burned in an earlier transaction; either way it is refused.
        if (
            OneTimeUseIdStorageLib.burnedInTx(msg.sender, account, pinned)
                == OneTimeUseIdStorageLib.BURN_NONE
        ) {
            return VALIDATION_FAILED;
        }
        return VALIDATION_SUCCESS;
    }

    /// @notice The settling check: refuses any Permit2 unlock this transaction's burn did not
    ///         nominate, and every ERC-1271 validation from any other caller
    /// @dev An executor-originated 1271 validation carries no burn (`checkAction` never ran for
    ///      it), so it is refused outright: a session carrying this policy runs only through
    ///      `verifyExecution`. This surface is `view`.
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
        if (OneTimeUseIdStorageLib.isExpired($pin.deadline)) return false;

        if (requestSender != address(PERMIT2)) return false;

        if (signature.length < PERMIT2_NONCE_START + NONCE_LENGTH) return false;
        uint256 presented =
            uint256(bytes32(signature[PERMIT2_NONCE_START:PERMIT2_NONCE_START + NONCE_LENGTH]));

        // Only a pre-claim that passed validation consumes the nonce, and that pre-claim is the
        // burn: a nomination left by a burn elsewhere cannot carry an order whose own pre-claim
        // never ran.
        if (!IPermit2IntentExecutor(INTENT_EXECUTOR)
                .isPermit2IntentNonceConsumed(presented, account)) {
            return false;
        }

        return OneTimeUseIdStorageLib.nomination(msg.sender, account, pinned)
            == OneTimeUseIdStorageLib.nominationOf(presented);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOneTimeUseIdPolicy
    function isUsed(
        address multiplexer,
        address account,
        uint256 id
    )
        external
        view
        override
        returns (bool)
    {
        return OneTimeUseIdStorageLib.spendRecord(multiplexer, account, id).burned;
    }

    /// @inheritdoc IOneTimeUseIdPolicy
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
        consumed =
            pinned != 0 && OneTimeUseIdStorageLib.spendRecord(multiplexer, account, pinned).burned;
    }

    /// @notice ERC-165 for both policy surfaces and the view surface
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IOneTimeUseIdPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
