// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";

// Contracts
import { SmartSessionEmissaryMock } from "@test/mock/SmartSessionEmissaryMock.sol";
import { AddressBook } from "@mocks/MockAddressBook.sol";

// Libraries
import { Solarray } from "solarray/Solarray.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @notice Replays an envelope that is valid for one context into another
contract SmartSessionERC7739_contextReplay_Test is SmartSessionERC7739_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    string constant PERMIT_TYPE =
        "Permit(address spender,uint256 value,uint256 nonce,uint256 deadline)";

    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice A second emissary deployment
    SmartSessionEmissaryMock internal otherEmissary;

    bytes internal encodeData;
    bytes32 internal hash;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        otherEmissary = new SmartSessionEmissaryMock(address(new AddressBook(MOCK_INTENT_EXECUTOR)));
        encodeData = abi.encode(address(0xBEEF), 1 ether, uint256(0), uint256(1_700_000_000));
        hash = _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, encodeData));
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_contextReplay_revertsWhen_OtherChainId(uint64 chainId) public {
        // Arrange - the account's eip712Domain reports the current chain id
        vm.assume(chainId != block.chainid);
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory signature = _signedEnvelope(permissionId, instance.account);
        (, bytes4 baseline) = _tryIsValidSignature(hash, signature);
        assertEq(baseline, ERC1271_MAGIC_VALUE, "Should accept it on the chain it is for");
        vm.chainId(chainId);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject it on another chain");
    }

    function test_contextReplay_revertsWhen_OtherAccount() public {
        // Arrange - the same session on two accounts, signed for `instance`
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        _enableContents(otherInstance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory signature = _signedEnvelope(permissionId, instance.account);

        // Act
        bytes4 result = _isValidSignature(instance, hash, signature);
        bytes4 otherResult = _isValidSignature(otherInstance, hash, signature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept it on the account it is for");
        assertEq(otherResult, INVALID_SIGNATURE, "Should reject it on another account");
    }

    function test_contextReplay_revertsWhen_OtherEmissaryWithoutTheSession() public {
        // Arrange
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory signature = _signedEnvelope(permissionId, instance.account);

        // Act
        vm.prank(instance.account);
        bytes4 result = otherEmissary.isValidSignatureWithSender(address(this), hash, signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject it where the session is not enabled");
    }

    function test_contextReplay_OtherEmissaryWithTheSameSession_ReturnsMagic() public {
        // Arrange - current behaviour: `TypedDataSign` takes its domain from the account's
        // eip712Domain, whose verifyingContract is the account, so the digest does not name the
        // emissary, and a second emissary with the same session enabled accepts the envelope
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        SmartSessionEmissaryMock emissary = smartSessionEmissary;
        smartSessionEmissary = otherEmissary;
        PermissionId otherPermissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        smartSessionEmissary = emissary;
        bytes memory signature = _signedEnvelope(permissionId, instance.account);

        // Act
        vm.prank(instance.account);
        bytes4 result = otherEmissary.isValidSignatureWithSender(address(this), hash, signature);

        // Assert
        assertEq(
            PermissionId.unwrap(otherPermissionId),
            PermissionId.unwrap(permissionId),
            "Should be the same session"
        );
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept it where the session is enabled");
    }

    function test_contextReplay_revertsWhen_OtherAppDomain() public {
        // Arrange - the description is enabled under both app domains. The envelope signed for
        // `appDomainSeparator` is re-pointed at `otherAppDomainSeparator`, with the matching hash
        string[] memory descriptions = Solarray.strings(PERMIT_TYPE);
        PermissionId permissionId = _enableContents(instance, appDomainSeparator, descriptions);
        _enableContents(instance, otherAppDomainSeparator, descriptions);
        bytes memory validatorSignature = _validatorSignature(instance.account);
        bytes memory signature = _envelope(
            permissionId,
            validatorSignature,
            otherAppDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );
        bytes32 otherHash = _appHash(otherAppDomainSeparator, _hashStruct(PERMIT_TYPE, encodeData));

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(otherHash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject it under another app domain");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice The session key's signature over the Permit for `account` under
    ///         `appDomainSeparator`
    function _validatorSignature(address account) internal view returns (bytes memory) {
        return _sign(
            sessionKey.privateKey,
            _typedDataSignDigest(
                account,
                appDomainSeparator,
                _typedDataSignTypehash("Permit", PERMIT_TYPE),
                _hashStruct(PERMIT_TYPE, encodeData)
            )
        );
    }

    function _signedEnvelope(
        PermissionId permissionId,
        address account
    )
        internal
        view
        returns (bytes memory)
    {
        return _envelope(
            permissionId,
            _validatorSignature(account),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );
    }
}
