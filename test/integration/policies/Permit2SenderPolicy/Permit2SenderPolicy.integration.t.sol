// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import {
    Permit2ClaimPolicy_Integration_Test
} from "../Permit2ClaimPolicy/Permit2ClaimPolicy.integration.t.sol";

// Contracts
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Permit2SenderPolicy } from "@policies/claim/permit2/Permit2SenderPolicy.sol";

// Interfaces
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Libraries
import { TestHelperLib } from "@compact-utils/tests/Environment.sol";

// Types
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { PolicyData } from "@smartsessions/DataTypes.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title Permit2SenderPolicy Integration Test
/// @notice A session whose ERC-1271 list is [Permit2ClaimPolicy, Permit2SenderPolicy] validates a
///         Permit2 claim signature only when Permit2 is the sender
contract Permit2SenderPolicy_Integration_Test is Permit2ClaimPolicy_Integration_Test {
    using TestHelperLib for *;

    Permit2SenderPolicy internal permit2SenderPolicy;

    function setUp() public virtual override {
        super.setUp();

        permit2SenderPolicy = new Permit2SenderPolicy(ISignatureTransfer(address(env.permit2)));
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the claim signature validates for Permit2 and for no other sender
    function test_integration_permit2Sender_acceptsOnlyRequestsSentByPermit2() public {
        _enableSessionWithSenderPolicy(true);
        bytes memory signature = _createSmartSessionSignature(_createPolicyData());

        assertTrue(_isValidSignatureFrom(address(env.permit2), signature), "Permit2: accepted");
        assertFalse(
            _isValidSignatureFrom(address(env.intentExecutor), signature),
            "intent executor: refused"
        );
        assertFalse(_isValidSignatureFrom(makeAddr("other"), signature), "other: refused");
        assertFalse(_isValidSignatureFrom(address(0), signature), "zero address: refused");
    }

    /// @notice Test without the sender policy the same signature validates for any sender, so the
    ///         refusals above come from the sender policy
    function test_integration_permit2Sender_control_claimPolicyAloneIgnoresTheSender() public {
        _enableSessionWithSenderPolicy(false);
        bytes memory signature = _createSmartSessionSignature(_createPolicyData());

        assertTrue(_isValidSignatureFrom(address(env.permit2), signature), "Permit2: accepted");
        assertTrue(
            _isValidSignatureFrom(address(env.intentExecutor), signature),
            "intent executor: accepted"
        );
        assertTrue(_isValidSignatureFrom(makeAddr("other"), signature), "other: accepted");
    }

    /// @notice Test the sender policy does not replace the claim policy: a claim signed for
    ///         another digest is refused even when Permit2 sends it
    function test_integration_permit2Sender_claimPolicyStillBindsTheDigest() public {
        _enableSessionWithSenderPolicy(true);
        bytes memory signature = _createSmartSessionSignature(_createPolicyData());

        vm.prank(address(env.permit2));
        try IERC1271(env.smartAccount1.account)
            .isValidSignature(keccak256("another digest"), signature) returns (
            bytes4 result
        ) {
            assertTrue(result != EIP1271_MAGIC_VALUE, "another digest: refused");
        } catch { }
    }

    /// @notice Test a Permit2 claim settles end to end through the router with both policies
    function test_integration_permit2Sender_permit2ClaimSettles() public {
        _enableSessionWithSenderPolicy(true);

        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        uint256 gas = _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );

        assertTrue(gas > 0, "Claim should succeed with Permit2 as the sender");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session whose ERC-1271 list pins the arbiter, with or without the sender
    ///         policy
    /// @dev Uses an order with no origin ops, so Permit2 is its only ERC-1271 sender
    function _enableSessionWithSenderPolicy(bool withSenderPolicy) internal {
        activeFieldMode = FIELD_ARBITER;

        $intent.element.mandate.originOps = intent.noExec.toOperation();
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);

        PolicyData[] memory policyDatas = new PolicyData[](withSenderPolicy ? 2 : 1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE), uint8(1), arbiter
            )
        });
        if (withSenderPolicy) {
            policyDatas[1] = PolicyData({ policy: address(permit2SenderPolicy), initData: "" });
        }

        vm.prank(env.smartAccount1.account);
        _enableSession(policyDatas, "permit2SenderSalt");
    }

    /// @notice Whether the account accepts `signature` over the claim digest when `sender` asks
    function _isValidSignatureFrom(address sender, bytes memory signature) internal returns (bool) {
        vm.prank(sender);
        try IERC1271(env.smartAccount1.account)
            .isValidSignature($intent.digest, signature) returns (
            bytes4 result
        ) {
            return result == EIP1271_MAGIC_VALUE;
        } catch {
            return false;
        }
    }
}
