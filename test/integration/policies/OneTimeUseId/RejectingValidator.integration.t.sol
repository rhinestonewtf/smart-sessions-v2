// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { EIP712Lib } from "@compact-utils/executor/StandaloneIntent/lib/EIP712Lib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { IPermit2IntentExecutor } from "@compact-utils/executor/interfaces/IPermit2Intent.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { ValidateSignature } from "@compact-utils/executor/VerifySignature/VerifySignature.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

/// @title A rejected session signature burns nothing
/// @notice The matrix signs with a permissive validator so the policy decides every case. Here the
///         session validator is the real `OwnableValidator`, which verifies ECDSA signatures. On
///         the entrypoints that revert on a failed validation - the Permit2 pre-claim and the
///         standalone settlement - a bad session signature reverts the whole executor frame, so the
///         burn `checkAction` wrote is rolled back and the id stays unspent. The same calls with
/// the owner's signature burn and run.
contract OneTimeUseIdRejectingValidator_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    uint256 internal constant NONCE = 4242;

    address internal owner;
    uint256 internal ownerKey;

    function _sessionValidator() internal view override returns (ISessionValidator) {
        return ISessionValidator(address(env.validator));
    }

    function _sessionValidatorInitData() internal view override returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return abi.encode(uint256(1), owners);
    }

    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](1);
        extra[0] = ActionData({
            actionTarget: address(oncePolicy),
            actionTargetSelector: IOneTimeUseIdPolicy.consumeFor.selector,
            actionPolicies: actionPolicies
        });
    }

    function setUp() public override {
        (owner, ownerKey) = makeAddrAndKey("sessionOwner");
        super.setUp();
        _enableSession(true);
    }

    /*//////////////////////////////////////////////////////////////
                                SIGNING
    //////////////////////////////////////////////////////////////*/

    /// @dev `OwnableValidator` recovers over the eth-signed hash of what it is handed
    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ECDSA.toEthSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _ownerSig(bytes32 digest) internal view returns (bytes memory) {
        return _emissarySig(_sign(ownerKey, digest));
    }

    /// @dev A well-formed signature from a key that is not the owner
    function _strangerSig(bytes32 digest) internal returns (bytes memory) {
        (, uint256 strangerKey) = makeAddrAndKey("stranger");
        return _emissarySig(_sign(strangerKey, digest));
    }

    /*//////////////////////////////////////////////////////////////
                             STANDALONE ROUTE
    //////////////////////////////////////////////////////////////*/

    function _standaloneOps(uint256 param)
        internal
        view
        returns (IStandaloneIntentExecutor.SingleChainOps memory signedOps)
    {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (param))
        });
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = 0;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
    }

    /// @dev The digest `executeSinglechainOps` verifies: the SingleChainOps struct hash under the
    ///      executor's own EIP-712 domain
    function _standaloneDigest(IStandaloneIntentExecutor.SingleChainOps memory signedOps)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                EIP712Lib.SINGLECHAINOPS_TYPEHASH,
                signedOps.account,
                signedOps.nonce,
                hasher.hashOps(signedOps.ops),
                EIP712Lib.NO_GASREFUND
            )
        );
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = env.intentExecutor.eip712Domain();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    /// @dev CONTROL: the owner's signature settles, so the refusal below is the signature.
    function test_control_theOwnersSignatureSettlesTheStandaloneRoute() public {
        IStandaloneIntentExecutor.SingleChainOps memory signedOps = _standaloneOps(42);
        signedOps.signature = _ownerSig(_standaloneDigest(signedOps));

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);

        assertTrue(_burned(), "the owner's settlement burned");
        assertEq(env.target.param(), 42, "and ran");
    }

    function test_aRejectedSignatureOnTheStandaloneRoute_burnsNothing() public {
        IStandaloneIntentExecutor.SingleChainOps memory signedOps = _standaloneOps(42);
        signedOps.signature = _strangerSig(_standaloneDigest(signedOps));

        vm.prank(env.solver.addr);
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        env.intentExecutor.executeSinglechainOps(signedOps);

        assertFalse(_burned(), "the revert rolled the validation-time burn back");
        assertTrue(env.target.param() != 42, "and nothing ran");
    }

    /*//////////////////////////////////////////////////////////////
                          PERMIT2 PRE-CLAIM ROUTE
    //////////////////////////////////////////////////////////////*/

    function _preClaimOps() internal view returns (Types.Operation memory) {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, NONCE))
        });
        return SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
    }

    function _emptyMandateStub()
        internal
        pure
        returns (IPermit2IntentExecutor.EIP712Permit2MandateStub memory)
    {
        return IPermit2IntentExecutor.EIP712Permit2MandateStub(
            bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0)
        );
    }

    /// @dev The digest `executePreClaimOpsWithPermit2Stub` verifies for `_preClaimOps()` under an
    ///      all-zero mandate stub, with `caller` folded in as the arbiter
    function _preClaimDigest(address caller) internal view returns (bytes32) {
        bytes32 mandate = EIP712TypeHashLib.hashMandateRaw({
            targetAttributes: bytes32(0),
            minGas: 0,
            preClaimOpsHash: hasher.hashOps(_preClaimOps()),
            destOpsHash: bytes32(0),
            qHash: bytes32(0)
        });
        bytes32 permit2Hash = EIP712TypeHashLib.hashPermit2({
            tokenInHash: bytes32(0),
            arbiter: caller,
            nonce: NONCE,
            expires: block.timestamp + 1 days,
            mandate: mandate
        });
        return hasher.hashTypedDataPermit2(block.chainid, permit2Hash);
    }

    function _preClaim(address caller, bytes memory sig) internal {
        vm.prank(caller);
        IPermit2IntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithPermit2Stub(
                env.smartAccount1.account,
                IPermit2IntentExecutor.EIP712Permit2Stub(NONCE, block.timestamp + 1 days),
                _emptyMandateStub(),
                _preClaimOps(),
                sig
            );
    }

    function _executorNonceConsumed() internal view returns (bool) {
        return IPermit2IntentExecutor(address(env.intentExecutor))
            .isPermit2IntentNonceConsumed(NONCE, env.smartAccount1.account);
    }

    /// @dev CONTROL: the owner's signature validates, burns and consumes the executor nonce.
    function test_control_theOwnersSignatureRunsThePermit2PreClaim() public {
        address caller = makeAddr("arbiter");

        _preClaim(caller, _ownerSig(_preClaimDigest(caller)));

        assertTrue(_burned(), "the owner's pre-claim burned");
        assertTrue(_executorNonceConsumed(), "and consumed the executor nonce");
    }

    function test_aRejectedSignatureOnThePermit2PreClaim_burnsNothing() public {
        address caller = makeAddr("arbiter");
        // Built before arming `expectRevert`: the digest helper makes staticcalls of its own.
        bytes memory sig = _strangerSig(_preClaimDigest(caller));

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _preClaim(caller, sig);

        assertFalse(_burned(), "the revert rolled the validation-time burn back");
        assertFalse(_executorNonceConsumed(), "and the executor nonce is untouched");
    }
}
