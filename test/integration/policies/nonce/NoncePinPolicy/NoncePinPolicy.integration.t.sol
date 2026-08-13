// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import {
    Permit2ClaimPolicy_Integration_Test
} from "@test/integration/policies/Permit2ClaimPolicy/Permit2ClaimPolicy.integration.t.sol";

// Contracts
import { NoncePinPolicy } from "@policies/nonce/NoncePinPolicy.sol";

// Libraries
import { Constants } from "@compact-utils/types/Constants.sol";

// Types
import { PolicyData } from "@smartsessions/DataTypes.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title NoncePinPolicy Integration Tests
/// @notice Proves the SUPPORTED configuration works end to end: NoncePinPolicy registered
///         alongside Permit2ClaimPolicy, against a real digest-bound permit settled through
///         real Permit2.
/// @dev The unit tests build their own payload from the same offset constants the contract
///      reads, so they are self-confirming on the one property that matters. These tests take
///      the payload the production encoder actually produces, so a wrong offset fails here.
contract NoncePinPolicy_Integration_Test is Permit2ClaimPolicy_Integration_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    NoncePinPolicy internal noncePinPolicy;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        noncePinPolicy = new NoncePinPolicy(address(env.intentExecutor), address(Constants.PERMIT2));
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The pinned nonce settles, proving the offsets line up with a real permit.
    /// @dev The intent's nonce comes from the shared harness and the payload is built by the
    ///      production encoder, so this fails if [20:52] does not land on the real nonce.
    function test_integration_noncePin_pinnedNonce_settles() public {
        _setupSessionWithNoncePin($intent.nonce);

        uint256 gas = _settle();

        assertTrue(gas > 0, "a claim carrying the pinned nonce should settle");
    }

    /// @notice A session pinned to a different nonce refuses the claim.
    /// @dev The complement of the test above. Without it, a policy that ignored the payload
    ///      entirely would still pass.
    function test_integration_noncePin_otherNonce_isRefused() public {
        _setupSessionWithNoncePin($intent.nonce + 1);

        bytes memory claimCalldata = _prepareClaim();

        vm.expectRevert();
        _settlePrepared(claimCalldata);
    }

    /// @notice One-time use: the second settlement of the pinned nonce reverts.
    /// @dev The property the whole design rests on, and the only test that exercises it against
    ///      real Permit2 rather than against our own bookkeeping. The pin makes every digest the
    ///      session can produce compete for this one slot, and Permit2 burns it on first use.
    function test_integration_noncePin_secondSettlement_reverts() public {
        _setupSessionWithNoncePin($intent.nonce);

        uint256 gas = _settle();
        assertTrue(gas > 0, "the first settlement should succeed");

        // Permit2 has now consumed the nonce; the same claim must not settle again
        bytes memory replay = _prepareClaim();

        vm.expectRevert();
        _settlePrepared(replay);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Enables a session holding BOTH policies, which is the only supported shape: the
    ///      claim policy binds the payload to the digest, and the pin constrains the nonce
    ///      within it. Registered alone, the pin proves nothing.
    function _setupSessionWithNoncePin(uint256 pinnedNonce) internal {
        activeFieldMode = FIELD_ARBITER;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](2);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // arbiter count
                arbiter
            )
        });
        policyDatas[1] =
            PolicyData({ policy: address(noncePinPolicy), initData: abi.encode(pinnedNonce) });

        _enableSession(policyDatas, "noncePinSalt");
    }

    /// @dev Builds the claim calldata and signs the session signature.
    /// @dev Kept separate from the call itself because `vm.expectRevert` binds to the very next
    ///      call: preparing inside the settling helper attached the expectation to a hash
    ///      helper instead of the settlement, so the revert tests passed while asserting
    ///      nothing about the claim.
    function _prepareClaim() internal returns (bytes memory claimCalldata) {
        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    /// @dev Settles a prepared claim. The only call in this helper is the claim itself.
    function _settlePrepared(bytes memory claimCalldata) internal returns (uint256 gas) {
        return _claim(block.chainid, abi.encodePacked(env.solver.addr), claimCalldata);
    }

    /// @dev Prepare and settle in one step, for the cases that expect success
    function _settle() internal returns (uint256 gas) {
        return _settlePrepared(_prepareClaim());
    }
}
