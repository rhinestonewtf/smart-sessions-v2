// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";
import {
    MockPermit2NonceExecutor
} from "@test/unit/policies/onetime/OneTimeUseIdPolicy/OneTimeUseIdPolicy.t.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";

// Types
import {
    PermissionId,
    ConfigId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @notice An ERC-7739 envelope for a session whose ERC-1271 policy is the `OneTimeUseIdPolicy`.
///         The session also carries the policy on its own `consumeFor` action, and the burn is
///         that action's check, called as the emissary validating it.
contract SmartSessionERC7739_policyInterplay_Test is SmartSessionERC7739_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    string constant PERMIT_TYPE =
        "Permit(address spender,uint256 value,uint256 nonce,uint256 deadline)";

    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    uint256 constant ID = 0xBEEF;
    uint256 constant NONCE = 1337;
    uint256 constant OTHER_NONCE = 4242;

    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    OneTimeUseIdPolicy internal oneTimeUseIdPolicy;
    MockPermit2NonceExecutor internal executor;

    PermissionId internal permissionId;

    bytes internal encodeData;
    bytes32 internal hash;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        executor = new MockPermit2NonceExecutor();
        oneTimeUseIdPolicy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), address(executor));
        permissionId = _enableOneTimeSession();
        encodeData = abi.encode(address(0xBEEF), 1 ether, uint256(0), uint256(1_700_000_000));
        hash = _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, encodeData));
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_policyInterplay_BurnedAndNominated_ReturnsMagic() public {
        // Arrange
        assertEq(_burn(NONCE), VALIDATION_SUCCESS, "Should burn the id");

        // Act
        (bool reverted, bytes4 result) =
            _tryIsValidSignature(PERMIT2, hash, _signedEnvelope(sessionKey.privateKey, NONCE));

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept the nominated order");
    }

    function test_policyInterplay_revertsWhen_SenderIsNotPermit2() public {
        // Arrange
        _burn(NONCE);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            address(this), hash, _signedEnvelope(sessionKey.privateKey, NONCE)
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a caller other than Permit2");
    }

    function test_policyInterplay_revertsWhen_IdNotBurned() public {
        // Act
        (bool reverted, bytes4 result) =
            _tryIsValidSignature(PERMIT2, hash, _signedEnvelope(sessionKey.privateKey, NONCE));

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject an order no burn nominated");
    }

    function test_policyInterplay_revertsWhen_BlobNamesOtherNonce() public {
        // Arrange
        _burn(NONCE);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            PERMIT2, hash, _signedEnvelope(sessionKey.privateKey, OTHER_NONCE)
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject an order the burn did not nominate");
    }

    function test_policyInterplay_revertsWhen_NonceNotConsumedByExecutor() public {
        // Arrange
        _burn(NONCE);
        executor.setUnconsumed(NONCE);

        // Act
        (bool reverted, bytes4 result) =
            _tryIsValidSignature(PERMIT2, hash, _signedEnvelope(sessionKey.privateKey, NONCE));

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject an order whose pre-claim did not run");
    }

    function test_policyInterplay_revertsWhen_EnvelopeTampered() public {
        // Arrange - the policy is satisfied, the hash is for 2 ether
        _burn(NONCE);
        bytes32 otherHash = _appHash(
            appDomainSeparator,
            _hashStruct(
                PERMIT_TYPE,
                abi.encode(address(0xBEEF), 2 ether, uint256(0), uint256(1_700_000_000))
            )
        );

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            PERMIT2, otherHash, _signedEnvelope(sessionKey.privateKey, NONCE)
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a hash the envelope does not bind");
    }

    function test_policyInterplay_revertsWhen_SignedByOtherKey() public {
        // Arrange
        _burn(NONCE);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            PERMIT2, hash, _signedEnvelope(vm.createWallet("otherKey").privateKey, NONCE)
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a signature from another key");
    }

    function test_policyInterplay_revertsWhen_IdBurnedAgain() public {
        // Arrange
        _burn(NONCE);

        // Act
        uint256 secondBurn = _burn(OTHER_NONCE);
        (, bytes4 nominated) =
            _tryIsValidSignature(PERMIT2, hash, _signedEnvelope(sessionKey.privateKey, NONCE));
        (, bytes4 renominated) = _tryIsValidSignature(
            PERMIT2, hash, _signedEnvelope(sessionKey.privateKey, OTHER_NONCE)
        );

        // Assert
        assertEq(secondBurn, VALIDATION_FAILED, "Should refuse a second burn of the id");
        assertTrue(
            oneTimeUseIdPolicy.isUsed(address(smartSessionEmissary), instance.account, ID),
            "Should record the id as spent"
        );
        assertEq(nominated, ERC1271_MAGIC_VALUE, "Should keep the first nomination");
        assertEq(renominated, INVALID_SIGNATURE, "Should reject the order of the refused burn");
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_policyInterplay_MagicOnlyWhenPolicyAndEnvelopeAccept(
        bool burn,
        bool fromPermit2,
        bool tamper,
        uint256 position
    )
        public
    {
        // Arrange - `tamper` flips a byte of the app domain or encodeData
        if (burn) _burn(NONCE);
        bytes memory signature = _signedEnvelope(sessionKey.privateKey, NONCE);
        if (tamper) {
            // Mode, permission id, offset, signature and the 84-byte claim blob come first
            uint256 start = 1 + 32 + 32 + 65 + 84;
            signature[bound(position, start, start + 32 + encodeData.length - 1)] ^= 0x01;
        }

        // Act
        (bool reverted, bytes4 result) =
            _tryIsValidSignature(fromPermit2 ? PERMIT2 : address(this), hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(
            result,
            burn && fromPermit2 && !tamper ? ERC1271_MAGIC_VALUE : INVALID_SIGNATURE,
            "Should accept only when the policy and the envelope both accept"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session whose ERC-1271 policy and `consumeFor` action policy pin `ID`
    function _enableOneTimeSession() internal returns (PermissionId) {
        address[] memory owners = new address[](1);
        owners[0] = sessionKey.addr;
        bytes memory pin = abi.encodePacked(bytes32(ID), bytes32(0));

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(oneTimeUseIdPolicy), initData: pin });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(oneTimeUseIdPolicy),
            actionTargetSelector: OneTimeUseIdPolicy.consumeFor.selector,
            actionPolicies: policyDatas
        });

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = PERMIT_TYPE;
        allowedContent[0].appDomainSeparator = appDomainSeparator;

        Session[] memory sessions = new Session[](1);
        sessions[0] = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256("policyInterplay"),
            sessionValidatorInitData: abi.encode(uint256(1), owners),
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: allowedContent, erc1271Policies: policyDatas
            }),
            actions: actions,
            claimPolicies: new PolicyData[](0)
        });

        vm.prank(instance.account);
        return smartSessionEmissary.enableSessions(sessions, NO_LOCK_TAG)[0];
    }

    /// @notice The action check of the session's own `consumeFor(ID, nonce)`, which burns `ID`
    ///         and nominates `nonce`
    function _burn(uint256 nonce) internal returns (uint256) {
        ConfigId configId = IdLib.toConfigId(
            IdLib.toActionPolicyId(
                permissionId,
                IdLib.toActionId(
                    address(oneTimeUseIdPolicy), OneTimeUseIdPolicy.consumeFor.selector
                )
            ),
            instance.account
        );
        vm.prank(address(smartSessionEmissary));
        return oneTimeUseIdPolicy.checkAction(
            configId,
            instance.account,
            address(oneTimeUseIdPolicy),
            0,
            abi.encodeCall(OneTimeUseIdPolicy.consumeFor, (ID, nonce))
        );
    }

    /// @notice An envelope for the Permit signed with `privateKey`, carrying a claim blob shaped
    ///         like `Permit2ClaimPolicy`'s: arbiter(20) . nonce(32) . mandate(32)
    function _signedEnvelope(
        uint256 privateKey,
        uint256 nonce
    )
        internal
        view
        returns (bytes memory)
    {
        return _envelope(
            permissionId,
            _sign(
                privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    _typedDataSignTypehash("Permit", PERMIT_TYPE),
                    _hashStruct(PERMIT_TYPE, encodeData)
                )
            ),
            abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(99))),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );
    }
}
