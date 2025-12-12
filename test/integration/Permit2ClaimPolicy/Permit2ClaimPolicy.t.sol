// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Contracts
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Permit2ClaimPolicy } from "@policies/claim/permit2/Permit2ClaimPolicy.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

// Libraries
import { TestHelperLib, CompactEnvironment } from "@compact-utils/tests/Environment.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { Element, Mandate, Target } from "@compact-utils/types/TheCompactStructs.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    PolicyData,
    ActionData,
    PermissionId,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";
import { Constants } from "@compact-utils/types/Constants.sol";
import {
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_RECIPIENT_IS_SPONSOR,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_TOKEN_OUT,
    FIELD_FILL_EXPIRY,
    MODE_CHECK_STORAGE
} from "@policies/claim/base/types/BaseDataTypes.sol";
import {
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { CALLTYPE_STATIC } from "erc7579/lib/ModeLib.sol";
import { IS_VALID_SIG_1271 } from "@lib/ModeLib.sol";

/// @title Permit2ClaimPolicy Integration Test
/// @notice Integration tests for Permit2ClaimPolicy validation via SmartSessionEmissary
contract Permit2ClaimPolicy_Integration_Test is CompactEnvironment, SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using TestHelperLib for *;
    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Intent data for Permit2 claims
    struct Permit2Intent {
        address sponsor;
        uint256 nonce;
        uint256 expires;
        Element element;
        bytes32 permit2Hash;
        bytes32 digest;
        bytes userEmissarySig;
    }

    Permit2Intent $intent;
    PermissionId defaultPermissionId;
    Permit2ClaimPolicy permit2ClaimPolicy;
    MockAdapter mockAdapter;
    address arbiter;
    uint8 internal activeFieldMode;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override(SmartSessionEmissary_Unit_Test) {
        // Deploy compact infrastructure (includes Permit2)
        _deployCompact();
        _deploySmartAccount({ create: true });

        // Deploy MockAdapter
        mockAdapter =
            new MockAdapter(address(env.router), address(env.compact), address(ADDRESSBOOK));
        arbiter = address(mockAdapter);

        _setClaimRoute(MockAdapter.mock_permit2_handleClaim.selector, address(mockAdapter));
        _sampleExecERC20(env.token2, 10);

        address recipient = env.smartAccount1.account;
        uint256 targetChainId = chains.targetChain;

        // Setup Permit2 intent
        $intent.sponsor = env.smartAccount1.account;
        $intent.nonce = 1337;
        $intent.expires = block.timestamp + 1 hours;

        $intent.element = Element({
            arbiter: arbiter,
            chainId: block.chainid, // Permit2 uses current chain
            idsAndAmounts: [uint256(uint160(address(env.token1))), 100 ether].into(),
            mandate: Mandate({
                target: Target({
                    recipient: recipient,
                    tokenOut: [uint256(uint160(address(env.token2))), 20 ether].into(),
                    targetChain: targetChainId,
                    fillExpiry: uint32(block.timestamp + 2 hours)
                }),
                minGas: 0,
                originOps: intent.targetExecutions.toOperation(),
                destOps: intent.noExec.toOperation(),
                q: ""
            })
        });

        // Compute Permit2 hash
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);

        // Call SmartSessionEmissary setup
        SmartSessionEmissary_Unit_Test.setUp();

        // Deploy Permit2ClaimPolicy
        permit2ClaimPolicy = new Permit2ClaimPolicy(address(Constants.PERMIT2));

        // Install SmartSessionEmissary as validator module on the account
        env.smartAccount1
            .installModule({
                moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
            });

        // Install fallback to account
        bytes memory _fallback = abi.encode(EIP712.eip712Domain.selector, CALLTYPE_STATIC, "");
        env.smartAccount1
            .installModule({
                moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: _fallback
            });

        // Deal tokens to the smart account for testing
        deal(address(env.token1), address(env.smartAccount1.account), 1_000_000 ether);
        // Approve PERMIT2 to spend token1
        vm.prank(env.smartAccount1.account);
        env.token1.approve(address(Constants.PERMIT2), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                                ARBITER
    //////////////////////////////////////////////////////////////*/

    /// @notice Test arbiter validation succeeds with correct arbiter
    function test_integration_verifyClaim_permit2_arbiter_valid() public {
        // Arrange
        _setupSessionWithArbiterConfig(arbiter);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed with correct arbiter");
    }

    /// @notice Test arbiter validation fails with wrong arbiter
    function test_integration_verifyClaim_permit2_arbiter_revertsWhen_wrongArbiter() public {
        // Arrange - configure wrong arbiter
        address wrongArbiter = makeAddr("wrongArbiter");
        _setupSessionWithArbiterConfig(wrongArbiter);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Test expiry (deadline) validation succeeds within bounds
    function test_integration_verifyClaim_permit2_expiry_valid() public {
        // Arrange - expires is block.timestamp + 1 hour, set bounds around it
        uint128 minDeadline = uint128(block.timestamp + 30 minutes);
        uint128 maxDeadline = uint128(block.timestamp + 2 hours);
        _setupSessionWithExpiryConfig(minDeadline, maxDeadline);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - deadline within bounds");
    }

    /// @notice Test expiry fails when deadline below min
    function test_integration_verifyClaim_permit2_expiry_revertsWhen_belowMin() public {
        // Arrange - set min higher than actual deadline
        uint128 minDeadline = uint128(block.timestamp + 2 hours);
        uint128 maxDeadline = uint128(block.timestamp + 3 hours);
        _setupSessionWithExpiryConfig(minDeadline, maxDeadline);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               TOKEN IN
    //////////////////////////////////////////////////////////////*/

    /// @notice Test tokenIn validation succeeds with whitelisted token
    function test_integration_verifyClaim_permit2_tokenIn_valid() public {
        // Arrange
        _setupSessionWithTokenInConfig(address(env.token1));

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - tokenIn whitelisted");
    }

    /// @notice Test tokenIn validation fails with non-whitelisted token
    function test_integration_verifyClaim_permit2_tokenIn_revertsWhen_wrongToken() public {
        // Arrange - whitelist token2 but intent uses token1
        _setupSessionWithTokenInConfig(address(env.token2));

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               RECIPIENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Test recipient validation succeeds with correct recipient
    function test_integration_verifyClaim_permit2_recipient_valid() public {
        // Arrange
        address recipient = $intent.element.mandate.target.recipient;
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithRecipientConfig(targetChainId, recipient);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - recipient matches");
    }

    /// @notice Test recipient validation fails with wrong recipient
    function test_integration_verifyClaim_permit2_recipient_revertsWhen_wrongRecipient() public {
        // Arrange
        address wrongRecipient = makeAddr("wrongRecipient");
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithRecipientConfig(targetChainId, wrongRecipient);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                          RECIPIENT IS SPONSOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Test recipientIsSponsor passes when recipient equals sponsor
    function test_integration_verifyClaim_permit2_recipientIsSponsor_valid() public {
        // Arrange - recipient is already env.smartAccount1.account (the sponsor)
        _setupSessionWithRecipientIsSponsorConfig();

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - recipient is sponsor");
    }

    /// @notice Test recipientIsSponsor fails when recipient is not sponsor
    function test_integration_verifyClaim_permit2_recipientIsSponsor_revertsWhen_notSponsor()
        public
    {
        // Arrange - modify recipient to be different from sponsor
        address differentRecipient = makeAddr("differentRecipient");
        $intent.element.mandate.target.recipient = differentRecipient;

        // Recompute hash after modification
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );

        _setupSessionWithRecipientIsSponsorConfig();

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                              FILL EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Test fillExpiry validation succeeds within bounds
    function test_integration_verifyClaim_permit2_fillExpiry_valid() public {
        // Arrange - fillExpiry is block.timestamp + 2 hours
        uint128 minFillExpiry = uint128(block.timestamp + 1 hours);
        uint128 maxFillExpiry = uint128(block.timestamp + 3 hours);
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithFillExpiryConfig(targetChainId, minFillExpiry, maxFillExpiry);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - fillExpiry within bounds");
    }

    /// @notice Test fillExpiry fails when below min
    function test_integration_verifyClaim_permit2_fillExpiry_revertsWhen_belowMin() public {
        // Arrange - set min higher than actual fillExpiry
        uint128 minFillExpiry = uint128(block.timestamp + 3 hours);
        uint128 maxFillExpiry = uint128(block.timestamp + 4 hours);
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithFillExpiryConfig(targetChainId, minFillExpiry, maxFillExpiry);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               TOKEN OUT
    //////////////////////////////////////////////////////////////*/

    /// @notice Test tokenOut validation succeeds with whitelisted token
    function test_integration_verifyClaim_permit2_tokenOut_valid() public {
        // Arrange
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithTokenOutConfig(targetChainId, address(env.token2));

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - tokenOut whitelisted");
    }

    /// @notice Test tokenOut validation fails with non-whitelisted token
    function test_integration_verifyClaim_permit2_tokenOut_revertsWhen_wrongToken() public {
        // Arrange - whitelist token1 but mandate uses token2 as tokenOut
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithTokenOutConfig(targetChainId, address(env.token1));

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               ORIGIN OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test originOps passes when required and ops present
    function test_integration_verifyClaim_permit2_originOps_requiredAndPresent() public {
        // Arrange - intent has originOps set
        _setupSessionWithOriginOpsConfig(true);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - originOps present");
    }

    /// @notice Test originOps fails when required but missing
    function test_integration_verifyClaim_permit2_originOps_revertsWhen_requiredButMissing()
        public
    {
        // Arrange - remove originOps from mandate
        $intent.element.mandate.originOps = intent.noExec.toOperation();

        // Recompute hash after modification
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );

        _setupSessionWithOriginOpsConfig(true);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /// @notice Test originOps passes when not required and missing
    function test_integration_verifyClaim_permit2_originOps_notRequiredAndMissing() public {
        // Arrange - remove originOps from mandate
        $intent.element.mandate.originOps = intent.noExec.toOperation();

        // Recompute hash after modification
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );

        _setupSessionWithOriginOpsConfig({ required: false });

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - originOps not required");
    }

    /*//////////////////////////////////////////////////////////////
                                DEST OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test destOps passes when required and ops present
    function test_integration_verifyClaim_permit2_destOps_requiredAndPresent() public {
        // Arrange - add destOps to mandate
        $intent.element.mandate.destOps = intent.targetExecutions.toOperation();

        // Recompute hash after modification
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );

        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithDestOpsConfig(targetChainId, true);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act
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

        assertTrue(gas > 0, "Claim should succeed - destOps present");
    }

    /// @notice Test destOps fails when required but missing
    function test_integration_verifyClaim_permit2_destOps_revertsWhen_requiredButMissing() public {
        // Arrange - destOps is already noExec
        uint256 targetChainId = $intent.element.mandate.target.targetChain;
        _setupSessionWithDestOpsConfig(targetChainId, true);

        Types.Order memory order = _getPermit2Order();

        bytes memory policyData = _createPolicyData();
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        // Act & Assert
        vm.expectRevert();
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                         SESSION SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Setup session with arbiter whitelist check
    function _setupSessionWithArbiterConfig(address expectedArbiter) internal {
        activeFieldMode = FIELD_ARBITER;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                expectedArbiter
            )
        });

        _enableSession(policyDatas, "arbiterSalt");
    }

    /// @notice Setup session with expiry (deadline) bounds check
    function _setupSessionWithExpiryConfig(uint128 min, uint128 max) internal {
        activeFieldMode = FIELD_EXPIRY;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(modeConfig, uint256(min) | (uint256(max) << 128))
        });

        _enableSession(policyDatas, "expirySalt");
    }

    /// @notice Setup session with tokenIn whitelist check
    /// @dev Permit2 tokenIn format: [count: 1][chainId: 32][token: 20]
    function _setupSessionWithTokenInConfig(address token) internal {
        activeFieldMode = FIELD_TOKEN_IN;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                uint256(block.chainid),
                token
            )
        });

        _enableSession(policyDatas, "tokenInSalt");
    }

    /// @notice Setup session with recipient whitelist check
    function _setupSessionWithRecipientConfig(uint256 chainId, address recipient) internal {
        activeFieldMode = FIELD_RECIPIENT;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                chainId,
                recipient
            )
        });

        _enableSession(policyDatas, "recipientSalt");
    }

    /// @notice Setup session with recipientIsSponsor check
    function _setupSessionWithRecipientIsSponsorConfig() internal {
        activeFieldMode = FIELD_RECIPIENT_IS_SPONSOR;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy), initData: abi.encodePacked(modeConfig)
        });

        _enableSession(policyDatas, "recipientIsSponsorSalt");
    }

    /// @notice Setup session with fillExpiry bounds check
    function _setupSessionWithFillExpiryConfig(uint256 chainId, uint128 min, uint128 max) internal {
        activeFieldMode = FIELD_FILL_EXPIRY;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                chainId,
                uint256(min) | (uint256(max) << 128)
            )
        });

        _enableSession(policyDatas, "fillExpirySalt");
    }

    /// @notice Setup session with tokenOut whitelist check
    function _setupSessionWithTokenOutConfig(uint256 chainId, address token) internal {
        activeFieldMode = FIELD_TOKEN_OUT;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                chainId,
                token
            )
        });

        _enableSession(policyDatas, "tokenOutSalt");
    }

    /// @notice Setup session with originOps check
    function _setupSessionWithOriginOpsConfig(bool required) internal {
        activeFieldMode = FIELD_ORIGIN_OPS;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                uint256(block.chainid),
                uint8(required ? 1 : 0)
            )
        });

        _enableSession(policyDatas, "originOpsSalt");
    }

    /// @notice Setup session with destOps check
    function _setupSessionWithDestOpsConfig(uint256 chainId, bool required) internal {
        activeFieldMode = FIELD_DEST_OPS;

        vm.prank(env.smartAccount1.account);

        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                modeConfig,
                uint8(1), // count
                chainId,
                uint8(required ? 1 : 0)
            )
        });

        _enableSession(policyDatas, "destOpsSalt");
    }

    /// @notice Helper to enable a session with given policy data
    function _enableSession(PolicyData[] memory policyDatas, string memory salt) internal {
        // Domain 0 enabled for direct mode
        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = "";
        allowedContent[0].appDomainSeparator = bytes32(0);
        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: allowedContent, erc1271Policies: policyDatas });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked(salt, block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, bytes12(0));
        defaultPermissionId = permissionIds[0];
    }

    /*//////////////////////////////////////////////////////////////
                           ORDER HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get Permit2 order from intent
    function _getPermit2Order() internal view returns (Types.Order memory order) {
        Element storage element = $intent.element;

        order = Types.Order({
            sponsor: $intent.sponsor,
            recipient: element.mandate.target.recipient,
            nonce: $intent.nonce,
            expires: $intent.expires,
            fillDeadline: element.mandate.target.fillExpiry,
            notarizedChainId: block.chainid, // Permit2 uses current chain
            targetChainId: element.mandate.target.targetChain,
            tokenIn: element.idsAndAmounts,
            tokenOut: element.mandate.target.tokenOut,
            preClaimOps: element.mandate.originOps,
            targetOps: element.mandate.destOps,
            qualifier: element.mandate.q,
            packedGasValues: Types.packGasValues(300_000, element.mandate.minGas)
        });
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _createSmartSessionSignature(bytes memory policyData)
        internal
        view
        returns (bytes memory)
    {
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        bytes memory sessionValidatorSignature = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            address(smartSessionEmissary),
            IS_VALID_SIG_1271,
            defaultPermissionId,
            uint256(sessionValidatorSignature.length) + 64,
            sessionValidatorSignature,
            policyData
        );
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY DATA HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates policy data for Permit2ClaimPolicy.check1271SignedAction
    /// @dev Layout:
    ///      [0:20]     arbiter (spender)
    ///      [20:52]    nonce
    ///      [52:84]    deadline (expires)
    ///      [84:...]   tokenIn (hash or expanded)
    ///      [...]      mandate (hash or expanded)
    function _createPolicyData() internal view returns (bytes memory) {
        Element storage element = $intent.element;

        // Header: arbiter + nonce + deadline
        bytes memory header = abi.encodePacked(element.arbiter, $intent.nonce, $intent.expires);

        // TokenIn data
        bytes memory tokenInData;
        if (activeFieldMode == FIELD_TOKEN_IN) {
            // Expanded: [count][token (32)][amount (32)]...
            tokenInData = abi.encodePacked(uint8(element.idsAndAmounts.length));
            for (uint256 i = 0; i < element.idsAndAmounts.length; i++) {
                tokenInData = abi.encodePacked(
                    tokenInData, element.idsAndAmounts[i][0], element.idsAndAmounts[i][1]
                );
            }
        } else {
            // Hash - use TokenPermissions format (no lockTag for Permit2)
            tokenInData = abi.encodePacked(_computeTokenPermissionsHash());
        }

        // Mandate data
        bytes memory mandateData;
        if (_needsExpandedTarget()) {
            mandateData = _createExpandedMandateData();
        } else if (_needsExpandedMandate()) {
            mandateData = _createPartiallyExpandedMandateData();
        } else {
            mandateData = abi.encodePacked(_computeMandateHash());
        }

        return abi.encodePacked(header, tokenInData, mandateData);
    }

    /// @notice Check if target fields need expansion
    function _needsExpandedTarget() internal view returns (bool) {
        return activeFieldMode == FIELD_RECIPIENT || activeFieldMode == FIELD_RECIPIENT_IS_SPONSOR
            || activeFieldMode == FIELD_FILL_EXPIRY || activeFieldMode == FIELD_TOKEN_OUT;
    }

    /// @notice Check if mandate fields need expansion (but not target)
    function _needsExpandedMandate() internal view returns (bool) {
        return activeFieldMode == FIELD_ORIGIN_OPS || activeFieldMode == FIELD_DEST_OPS;
    }

    /// @notice Create expanded mandate data when target fields are checked
    function _createExpandedMandateData() internal view returns (bytes memory) {
        Target storage target = $intent.element.mandate.target;

        bytes memory targetData;
        if (activeFieldMode == FIELD_TOKEN_OUT) {
            // TokenOut expanded
            targetData = abi.encodePacked(
                target.recipient,
                uint256(target.targetChain),
                uint256(target.fillExpiry),
                uint8(target.tokenOut.length)
            );
            for (uint256 i = 0; i < target.tokenOut.length; i++) {
                targetData =
                    abi.encodePacked(targetData, target.tokenOut[i][0], target.tokenOut[i][1]);
            }
        } else {
            // Recipient/FillExpiry/RecipientIsSponsor expanded
            bytes32 tokenOutHash = _computeTokenOutHash();
            targetData = abi.encodePacked(
                target.recipient,
                uint256(target.targetChain),
                uint256(target.fillExpiry),
                tokenOutHash
            );
        }

        // Rest of mandate
        bytes32 originOpsHash = hasher.hashOps($intent.element.mandate.originOps);
        bytes32 destOpsHash = hasher.hashOps($intent.element.mandate.destOps);
        bytes32 qHash = keccak256($intent.element.mandate.q);

        return abi.encodePacked(
            targetData, uint128($intent.element.mandate.minGas), originOpsHash, destOpsHash, qHash
        );
    }

    /// @notice Create partially expanded mandate data (target hashed, ops expanded)
    function _createPartiallyExpandedMandateData() internal view returns (bytes memory) {
        bytes32 targetHash = _computeTargetHash();
        bytes32 originOpsHash = hasher.hashOps($intent.element.mandate.originOps);
        bytes32 destOpsHash = hasher.hashOps($intent.element.mandate.destOps);
        bytes32 qHash = keccak256($intent.element.mandate.q);

        return abi.encodePacked(
            targetHash,
            uint256($intent.element.mandate.target.targetChain),
            uint128($intent.element.mandate.minGas),
            originOpsHash,
            destOpsHash,
            qHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                          HASH COMPUTATION
    //////////////////////////////////////////////////////////////*/

    function _computeTokenPermissionsHash() internal view returns (bytes32) {
        // For Permit2, tokenIn is just token addresses (no lockTag)
        uint256[2][] storage idsAndAmounts = $intent.element.idsAndAmounts;
        return this.computeTokenPermissionsHashExternal(idsAndAmounts);
    }

    function computeTokenPermissionsHashExternal(uint256[2][] calldata tokenPermissions)
        external
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);
    }

    function _computeMandateHash() internal view returns (bytes32) {
        bytes32 targetHash = _computeTargetHash();
        bytes32 originOpsHash = hasher.hashOps($intent.element.mandate.originOps);
        bytes32 destOpsHash = hasher.hashOps($intent.element.mandate.destOps);
        bytes32 qHash = keccak256($intent.element.mandate.q);

        return EIP712TypeHashLib.hashMandateRaw(
            targetHash, uint128($intent.element.mandate.minGas), originOpsHash, destOpsHash, qHash
        );
    }

    function _computeTargetHash() internal view returns (bytes32) {
        bytes32 tokenOutHash = _computeTokenOutHash();
        Target storage target = $intent.element.mandate.target;

        return EIP712TypeHashLib.hashTargetAttributesRaw(
            target.recipient, tokenOutHash, target.targetChain, target.fillExpiry
        );
    }

    function _computeTokenOutHash() internal view returns (bytes32) {
        return this.computeTokenOutHashExternal($intent.element.mandate.target.tokenOut);
    }

    function computeTokenOutHashExternal(uint256[2][] calldata tokenOut)
        external
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashTokenOut(tokenOut);
    }
}
