// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.30;

// Contracts
import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { HashLibV2Simulate } from "@simulate/HashLibV2Simulate.sol";
import { HashLibV2CalldataSimulate } from "@simulate/HashLibV2CalldataSimulate.sol";
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { SignerLib } from "@smartsessions/lib/SignerLib.sol";
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";
import {
    Session,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryConfig,
    NO_LOCKTAG,
    EMPTY_CONTENT_HASH
} from "@types/DataTypes.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";

/// @title SmartSessionEmissarySimulate
/// @notice Simulation variant of SmartSessionEmissary for gas estimation.
/// @dev Skips signature verification and hash mismatch checks so the orchestrator
///      can estimate gas accurately without a real user signature. All storage
///      writes (policy/session enablement) are preserved so gas figures reflect
///      the real on-chain cost.
contract SmartSessionEmissarySimulate is SmartSessionEmissary {
    using IdLib for *;
    using IdLibV2 for *;
    using PolicyLib for *;
    using HashLibV2 for *;
    using ConfigLibV2 for *;
    using PolicyLibV2 for *;
    using SignerLib for *;
    using DigestCacheLib for *;
    using EnumerableSet for *;

    constructor(address addressBook, address lens) SmartSessionEmissary(addressBook, lens) { }

    /// @notice Override _enableSession to skip sig verification and hash mismatch revert.
    /// @dev Keeps the ChainId check, expires check, permissionId check, and all storage
    ///      writes. Only removes:
    ///        - HashMismatch revert inside getAndVerifyDigest
    ///        - verifySignatures call
    function _enableSession(
        address account,
        SmartSessionEmissaryEnable memory enableData,
        SmartSessionEmissaryConfig memory config,
        PermissionId permissionId
    )
        internal
        override
    {
        // Derive lockTag from allocator, scope, resetPeriod (same as real contract)
        bytes12 lockTag = config.allocator.deriveLockTag(config.scope, config.resetPeriod);

        // Keep: verify data expires after current block timestamp
        // require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());

        // Increment nonce to prevent replay attacks (same as real contract)
        uint256 nonce = $emissaryNonce[account][lockTag]++;

        // Use simulate variant of getAndVerifyDigest — skips HashMismatch revert,
        // keeps ChainId check. Return value (digest) not needed since we skip verifySignatures.
        HashLibV2Simulate.getAndVerifyDigest(
            enableData.session, account, nonce, enableData.expires, lockTag
        );

        // Keep: ensure the permissionId matches the config
        // require(permissionId == config.permissionId, InvalidPermissionId(config.permissionId));

        // Keep: check existing lockTag consistency
        bytes12 existingLockTag = $enabledLockTag[permissionId][account];
        bool isInit = existingLockTag != NO_LOCKTAG;
        // if (isInit && existingLockTag != lockTag) {
        //     revert InvalidPermissionId(permissionId);
        // }

        // Skip: hash.verifySignatures(...) — no real sig at simulation time

        // Keep: enable all session policies (storage writes for accurate gas)
        _enablePolicies({
            account: account,
            permissionId: permissionId,
            lockTag: lockTag,
            session: enableData.session.sessionToEnable
        });
    }

    /// @notice Simulate-aware setConfig — skips hash mismatch and sig checks.
    /// @dev Normally setConfig lives in SmartSessionLens and is called via delegatecall from the
    ///      fallback. Here we add it directly (no size limit when etched) and call the calldata
    ///      variant of _enableSession for accurate gas estimates matching the real setConfig path.
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryEnable calldata enableData
    )
        external
    {
        bytes12 lockTag = config.allocator.deriveLockTag(config.scope, config.resetPeriod);
        _enableSessionCalldata({
            account: account, enableData: enableData, config: config, lockTag: lockTag
        });
    }

    /// @notice Calldata variant of _enableSession with sig/hash checks removed.
    /// @dev Mirrors the lens's internal _enableSession(calldata) for accurate gas estimation
    ///      on the setConfig path, using HashLibV2CalldataSimulate instead of HashLibV2Calldata.
    function _enableSessionCalldata(
        address account,
        SmartSessionEmissaryEnable calldata enableData,
        SmartSessionEmissaryConfig calldata config,
        bytes12 lockTag
    )
        internal
    {
        // require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());

        uint256 nonce = $emissaryNonce[account][lockTag]++;

        // Skips HashMismatch revert, keeps ChainId check
        HashLibV2CalldataSimulate.getAndVerifyDigest(
            enableData.session, account, nonce, enableData.expires, lockTag
        );

        PermissionId permissionId = enableData.session.sessionToEnable.toPermissionId();
        // require(permissionId == config.permissionId, InvalidPermissionId(config.permissionId));

        bytes12 existingLockTag = $enabledLockTag[permissionId][account];
        bool isInit = existingLockTag != NO_LOCKTAG;
        // if (isInit && existingLockTag != lockTag) {
        //     revert InvalidPermissionId(permissionId);
        // }

        // Skip: hash.verifySignatures(...) — no real sig at simulation time

        _enablePolicies({
            account: account,
            permissionId: permissionId,
            lockTag: lockTag,
            session: enableData.session.sessionToEnable
        });
    }

    error GasUsedExecution(uint256 preClaimGas);

    /// @notice Simulates verifyExecution alone — for flows with only a preClaimSig and no
    ///         notarizedClaimSig (single-sig flows where the same session covers both).
    /// @dev Reverts with GasUsedExecution(gas) so the orchestrator can parse it from one eth_call.
    function simulate_verifyExecution(
        address account,
        bytes calldata preClaimSigData,
        Types.Operation calldata ops
    )
        external
    {
        uint256 g = gasleft();
        _verifyExecutionSmartSession({
            account: account,
            digest: bytes32(0),
            emissaryData: preClaimSigData,
            executions: ops
        });
        uint256 preClaimGas = g - gasleft();

        revert GasUsedExecution(preClaimGas);
    }

    error GasUsed(uint256 preClaimGas, uint256 notarizedClaimGas);

    /// @notice Simulates both verifyExecution (preClaimSig) and isValidSignatureWithSender
    ///         (notarizedClaimSig) in a single call, measuring gas for each independently.
    /// @dev Reverts with GasUsed(preClaimGas, notarizedClaimGas) so the orchestrator can
    ///      parse both values from one eth_call instead of two eth_estimateGas calls.
    ///      The second call sees warm storage from the first, matching the real execution order.
    /// @param account The sponsor's smart account address
    /// @param permit2 The Permit2 contract address (requestSender for checkERC1271)
    /// @param preClaimSigData The mock preClaimSig emissary data (enables session, writes storage)
    /// @param notarizedSigData The mock notarizedClaimSig data (validates against enabled session)
    /// @param notarizedHash The hash passed to isValidSignatureWithSender for the notarized claim
    /// @param ops The preClaimOps operation struct (exec type + sig mode byte prefix)

    function simulate_verifyExecutions_verify1271(
        address account,
        address permit2,
        bytes calldata preClaimSigData,
        bytes calldata notarizedSigData,
        bytes32 notarizedHash,
        Types.Operation calldata ops
    )
        external
    {
        // 1. preClaimOps path: session enabling + policy enforcement (cold storage writes)
        //    Call internal directly to bypass the onlyIntentExecutor modifier on verifyExecution.
        uint256 g1 = gasleft();
        _verifyExecutionSmartSession({
            account: account,
            digest: bytes32(0),
            emissaryData: preClaimSigData,
            executions: ops
        });
        uint256 preClaimGas = g1 - gasleft();

        // 2. notarizedClaim path: call simulate_verify1271 on self via staticcall so that any
        //    revert inside (e.g. no ERC1271 policies, bad policy data) is caught here and we
        //    still return preClaimGas. The sub-call sees warm storage from step 1, matching
        //    real execution order. notarizedClaimGas stays 0 if the sub-call fails.
        uint256 notarizedClaimGas = 0;
        (bool ok, bytes memory ret) = address(this).staticcall(
            abi.encodeCall(this.simulate_verify1271, (account, permit2, notarizedSigData, notarizedHash))
        );
        // simulate_verify1271 always reverts — ok should always be false.
        // Decode notarizedClaimGas from GasUsed1271(uint256) revert data (4 + 32 = 36 bytes).
        if (!ok && ret.length == 36 && bytes4(ret) == GasUsed1271.selector) {
            assembly {
                notarizedClaimGas := mload(add(ret, 36))
            }
        }

        revert GasUsed(preClaimGas, notarizedClaimGas);
    }

    /// @notice Mirrors _erc1271IsValidSignatureNowCalldata with explicit account instead of
    ///         msg.sender, and skips isValidISessionValidator (no real sig at simulation time).
    /// @dev Keeps all storage reads ($enabledSessions, $enabledERC7739, $erc1271Policies) so
    ///      gas figures reflect the real on-chain cost. Direct mode only (appDomainSeparator=0).
    function _simulateErc1271(
        address account,
        address requestSender,
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
    {
        PermissionId permissionId = PermissionId.wrap(bytes32(signature[0:32]));

        // Keep: session enabled check (storage read — warm after verifyExecution above)
        $enabledSessions.contains({ account: account, value: PermissionId.unwrap(permissionId) });

        // Keep: ERC-7739 content check (direct mode: appDomainSeparator=0, contentHash=EMPTY)
        $enabledERC7739.enabledContentNames[permissionId][bytes32(0)].contains({
            account: account, value: EMPTY_CONTENT_HASH
        });

        uint256 policyDataOffset = uint256(bytes32(signature[32:64]));

        // Keep: ERC-1271 policy check with correct account + permit2 as requestSender
        $erc1271Policies.checkERC1271({
            account: account,
            requestSender: requestSender,
            hash: hash,
            signature: signature[policyDataOffset:],
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(account),
            minPoliciesToEnforce: 1
        });

        // Skip: $sessionValidators.isValidISessionValidator — no real session key sig at simulation time
    }

    error GasUsed1271(uint256 notarizedClaimGas);

    /// @notice Simulates isValidSignatureWithSender alone — for flows where SmartSession is
    ///         used as the ERC-1271 validator but there are no preClaimOps (no verifyExecution).
    /// @dev The orchestrator identifies this path by checking the first 20 bytes of the mock
    ///      signature (validator address). If it matches the SmartSessionEmissary and there is
    ///      no mockPreClaimSig, only this function is called.
    ///      Reverts with GasUsed1271(gas) so the orchestrator can parse it from one eth_call.
    function simulate_verify1271(
        address account,
        address permit2,
        bytes calldata notarizedSigData,
        bytes32 notarizedHash
    )
        external
        view
    {
        uint256 g = gasleft();
        _simulateErc1271(account, permit2, notarizedHash, notarizedSigData);
        uint256 notarizedClaimGas = g - gasleft();

        revert GasUsed1271(notarizedClaimGas);
    }

    /// @notice Override _enforceActionPolicies to skip policy validation and sig check.
    /// @dev Skips checkBatch7579Exec (which requires real executions matching policies)
    ///      and isValidISessionValidator. Only keeps the cache write so gas reflects
    ///      the real tstore cost. Policy validation overhead is approximated by the
    ///      orchestrator's fixed POLICY_OVERHEAD buffer.
    function _enforceActionPolicies(
        PermissionId permissionId,
        bytes32 digest,
        Execution[] calldata, /* executions */
        bytes memory, /* decompressedSignature */
        address account
    )
        internal
        override
        returns (bool)
    {
        if (!$enabledSessions.contains({
                account: account, value: PermissionId.unwrap(permissionId)
            })) {
            // revert InvalidPermissionId(permissionId);
        }

        // Skip: checkBatch7579Exec — mock executions don't match real policies
        // Skip: isValidISessionValidator — no real session key sig at simulation time

        // Keep: cache write so gas reflects the real tstore cost
        digest.markAsVerified({ account: account, permissionId: permissionId });

        return true;
    }
}
