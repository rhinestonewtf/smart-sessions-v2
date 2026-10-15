// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";

// Libraries
import { LibString } from "solady/utils/LibString.sol";
import { Solarray } from "solarray/Solarray.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

contract SmartSessionERC7739_erc1271IsValidSignatureViaNestedEIP712_Test is
    SmartSessionERC7739_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    string constant PERMIT_TYPE =
        "Permit(address spender,uint256 value,uint256 nonce,uint256 deadline)";
    string constant TYPED_DATA_SIGN_PERMIT = "TypedDataSign(Permit contents,string name,"
        "string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        "Permit(address spender,uint256 value,uint256 nonce,uint256 deadline)";
    string constant TYPED_DATA_SIGN_ORDER_OF_PERMIT = "TypedDataSign(Order contents,string name,"
        "string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        "Permit(address spender,uint256 value,uint256 nonce,uint256 deadline)";

    /// @dev The EIP-712 specification's example: `Mail` sorts before `Person`, so the primary
    /// type comes first in both its `encodeType` and the `TypedDataSign` encoding.
    string constant MAIL_TYPE =
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
    string constant PERSON_TYPE = "Person(string name,address wallet)";
    string constant TYPED_DATA_SIGN_MAIL = "TypedDataSign(Mail contents,string name,"
        "string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
    bytes32 constant MAIL_DOMAIN_SEPARATOR =
        0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f;
    bytes32 constant MAIL_CONTENTS =
        0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e;
    bytes32 constant MAIL_HASH = 0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2;

    /// @dev `Outer` sorts after its dependency `Inner`.
    string constant OUTER_TYPE = "Outer(Inner a,uint256 b)Inner(uint256 x)";
    string constant OUTER_TYPE_SORTED = "Inner(uint256 x)Outer(Inner a,uint256 b)";
    string constant INNER_TYPE = "Inner(uint256 x)";
    /// @dev The ERC-7739 typehash formula with `contentsType` primary type first.
    string constant TYPED_DATA_SIGN_OUTER = "TypedDataSign(Outer contents,string name,"
        "string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        "Outer(Inner a,uint256 b)Inner(uint256 x)";
    /// @dev The EIP-712 `encodeType` of `TypedDataSign`, dependencies sorted by name.
    string constant TYPED_DATA_SIGN_OUTER_SORTED = "TypedDataSign(Outer contents,string name,"
        "string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        "Inner(uint256 x)Outer(Inner a,uint256 b)";

    /*//////////////////////////////////////////////////////////////
                         SESSION KEY SIGNATURES
    //////////////////////////////////////////////////////////////*/

    function test_erc1271IsValidSignatureViaNestedEIP712_ImplicitMode_Success() public {
        // Arrange
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account, appDomainSeparator, keccak256(bytes(TYPED_DATA_SIGN_PERMIT)), contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept an implicit-mode signature");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_ExplicitMode_Success() public {
        // Arrange
        bytes memory description = abi.encodePacked(PERMIT_TYPE, "Permit");
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account, appDomainSeparator, keccak256(bytes(TYPED_DATA_SIGN_PERMIT)), contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            description
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept an explicit-mode signature");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_revertsWhen_SignatureCoversDifferentStruct()
        public
    {
        // Arrange - the session key signed a Permit for 2 ether, the envelope carries 1 ether
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
            _hashStruct(PERMIT_TYPE, _permitEncodeData(2 ether))
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );

        // Act
        bytes4 result = _isValidSignature(
            instance, _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, encodeData)), signature
        );

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a signature over another struct");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_revertsWhen_HashIsOfAnotherStructOfTheSameType()
        public
    {
        // Arrange - the envelope and the session key agree on 1 ether, the hash is for 2 ether
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
            _hashStruct(PERMIT_TYPE, encodeData)
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );
        bytes32 hash =
            _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, _permitEncodeData(2 ether)));

        // Act
        bytes4 result = _isValidSignature(instance, hash, signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a hash of another struct");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_revertsWhen_SignatureCoversDifferentAppDomain()
        public
    {
        // Arrange
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            otherAppDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a signature for another app domain");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_revertsWhen_SignatureCoversDifferentAccount()
        public
    {
        // Arrange - the same session on two accounts, signed for the other one
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        _enableContents(otherInstance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            otherInstance.account,
            appDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );
        bytes32 hash = _appHash(appDomainSeparator, contents);

        // Act
        bytes4 result = _isValidSignature(instance, hash, signature);
        bytes4 otherResult = _isValidSignature(otherInstance, hash, signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a signature for another account");
        assertEq(otherResult, ERC1271_MAGIC_VALUE, "Should accept it on the account it is for");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_revertsWhen_SignedByDifferentKey() public {
        // Arrange
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account, appDomainSeparator, keccak256(bytes(TYPED_DATA_SIGN_PERMIT)), contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(vm.createWallet("otherKey").privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a signature from another key");
    }

    /*//////////////////////////////////////////////////////////////
                              NESTED TYPES
    //////////////////////////////////////////////////////////////*/

    function test_erc1271IsValidSignatureViaNestedEIP712_NestedType_EIP712MailExample_Success()
        public
    {
        // Arrange - the hash and contents are the EIP-712 specification's values
        PermissionId permissionId =
            _enableContents(instance, MAIL_DOMAIN_SEPARATOR, Solarray.strings(MAIL_TYPE));
        bytes memory encodeData = abi.encode(
            _hashPerson("Cow", 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826),
            _hashPerson("Bob", 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB),
            keccak256("Hello, Bob!")
        );
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            MAIL_DOMAIN_SEPARATOR,
            keccak256(bytes(TYPED_DATA_SIGN_MAIL)),
            MAIL_CONTENTS
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            MAIL_DOMAIN_SEPARATOR,
            encodeData,
            bytes(MAIL_TYPE)
        );

        // Act
        bytes4 result = _isValidSignature(instance, MAIL_HASH, signature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept the EIP-712 Mail example");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_NestedType_PrimaryFirst_Success() public {
        // Arrange
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(OUTER_TYPE));
        bytes memory encodeData = _outerEncodeData();
        bytes32 contents = _hashStruct(OUTER_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account, appDomainSeparator, keccak256(bytes(TYPED_DATA_SIGN_OUTER)), contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(OUTER_TYPE)
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a primary-first nested type");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_NestedType_revertsWhen_ExplicitModeDependenciesFirst()
        public
    {
        // Arrange - contents derive from the sorted type string, which is not Outer's typehash
        bytes memory description = abi.encodePacked(OUTER_TYPE_SORTED, "Outer");
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = _outerEncodeData();
        bytes32 contents = _hashStruct(OUTER_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_OUTER_SORTED)),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            description
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a dependencies-first type string");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_NestedType_revertsWhen_SignedOverSortedTypedDataSign()
        public
    {
        // Arrange - current behaviour: the typehash appends `contentsType` primary type first,
        // so a signature over the EIP-712 encoding of `TypedDataSign`, whose dependencies are
        // sorted, does not match when the primary type sorts after a dependency
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(OUTER_TYPE));
        bytes memory encodeData = _outerEncodeData();
        bytes32 contents = _hashStruct(OUTER_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_OUTER_SORTED)),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(OUTER_TYPE)
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject the sorted TypedDataSign encoding");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_NestedType_revertsWhen_TypeStringIsNotAppType()
        public
    {
        // Arrange - the session key signs a type string the app did not hash
        string memory otherType = "Outer(Inner a,uint256 b)Inner(uint256 y)";
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(otherType));
        bytes memory encodeData = _outerEncodeData();
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            _typedDataSignTypehash("Outer", otherType),
            _hashStruct(otherType, encodeData)
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            bytes(otherType)
        );

        // Act
        bytes4 result = _isValidSignature(
            instance, _appHash(appDomainSeparator, _hashStruct(OUTER_TYPE, encodeData)), signature
        );

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a type string that is not the app's");
    }

    /*//////////////////////////////////////////////////////////////
                         EXPLICIT CONTENTS NAME
    //////////////////////////////////////////////////////////////*/

    function test_erc1271IsValidSignatureViaNestedEIP712_ExplicitName_DiffersFromPrimaryType_Success()
        public
    {
        // Arrange - current behaviour: the explicit-mode name need not be the primary type of
        // `contentsType`. Contents still derive from the Permit type, so the hash binds the
        // Permit struct; the name only changes the TypedDataSign typehash the session key signs.
        bytes memory description = abi.encodePacked(PERMIT_TYPE, "Order");
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_ORDER_OF_PERMIT)),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            description
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a name other than the primary type");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_ExplicitName_revertsWhen_SignedUnderPrimaryTypeName()
        public
    {
        // Arrange
        bytes memory description = abi.encodePacked(PERMIT_TYPE, "Order");
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account, appDomainSeparator, keccak256(bytes(TYPED_DATA_SIGN_PERMIT)), contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            description
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should bind the explicit name into the signed hash");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_ExplicitName_revertsWhen_NameIsInvalid()
        public
    {
        // Arrange - a name starting with a lowercase letter is not a valid contents name
        bytes memory description = abi.encodePacked(PERMIT_TYPE, "order");
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(string(description)));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            _typedDataSignTypehash("order", PERMIT_TYPE),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            description
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject an invalid contents name");
    }

    /*//////////////////////////////////////////////////////////////
                            ALLOWED CONTENTS
    //////////////////////////////////////////////////////////////*/

    function test_erc1271IsValidSignatureViaNestedEIP712_Allowlist_revertsWhen_DescriptionNotEnabled()
        public
    {
        // Arrange - the explicit form selects the same type and name, so the session key signs
        // the same digest, but the session only enabled the implicit form
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account, appDomainSeparator, keccak256(bytes(TYPED_DATA_SIGN_PERMIT)), contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            abi.encodePacked(PERMIT_TYPE, "Permit")
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(appDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject a description that is not enabled");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_Allowlist_revertsWhen_EnabledUnderOtherAppDomain()
        public
    {
        // Arrange - consistent for the other app domain, enabled only for `appDomainSeparator`
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes32 contents = _hashStruct(PERMIT_TYPE, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            otherAppDomainSeparator,
            keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            otherAppDomainSeparator,
            encodeData,
            bytes(PERMIT_TYPE)
        );

        // Act
        bytes4 result =
            _isValidSignature(instance, _appHash(otherAppDomainSeparator, contents), signature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject an app domain that is not enabled");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_Allowlist_TwoTypes_EachSignsOwnStruct()
        public
    {
        // Arrange
        PermissionId permissionId = _enableContents(
            instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE, OUTER_TYPE)
        );
        bytes memory permitEncodeData = _permitEncodeData(1 ether);
        bytes32 permitContents = _hashStruct(PERMIT_TYPE, permitEncodeData);
        bytes memory permitSignature = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
                    permitContents
                )
            ),
            appDomainSeparator,
            permitEncodeData,
            bytes(PERMIT_TYPE)
        );
        bytes memory outerEncodeData = _outerEncodeData();
        bytes32 outerContents = _hashStruct(OUTER_TYPE, outerEncodeData);
        bytes memory outerSignature = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    keccak256(bytes(TYPED_DATA_SIGN_OUTER)),
                    outerContents
                )
            ),
            appDomainSeparator,
            outerEncodeData,
            bytes(OUTER_TYPE)
        );

        // Act
        bytes4 permitResult = _isValidSignature(
            instance, _appHash(appDomainSeparator, permitContents), permitSignature
        );
        bytes4 outerResult = _isValidSignature(
            instance, _appHash(appDomainSeparator, outerContents), outerSignature
        );

        // Assert
        assertEq(permitResult, ERC1271_MAGIC_VALUE, "Should accept the Permit struct");
        assertEq(outerResult, ERC1271_MAGIC_VALUE, "Should accept the Outer struct");
    }

    function test_erc1271IsValidSignatureViaNestedEIP712_Allowlist_TwoTypes_revertsWhen_StructUnderOtherType()
        public
    {
        // Arrange - each struct's encodeData under the other enabled type, signed as the
        // emissary reads it, for the hash of the struct under its own type
        PermissionId permissionId = _enableContents(
            instance, appDomainSeparator, Solarray.strings(PERMIT_TYPE, OUTER_TYPE)
        );
        bytes memory permitEncodeData = _permitEncodeData(1 ether);
        bytes memory permitAsOuter = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    keccak256(bytes(TYPED_DATA_SIGN_OUTER)),
                    _hashStruct(OUTER_TYPE, permitEncodeData)
                )
            ),
            appDomainSeparator,
            permitEncodeData,
            bytes(OUTER_TYPE)
        );
        bytes memory outerEncodeData = _outerEncodeData();
        bytes memory outerAsPermit = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    keccak256(bytes(TYPED_DATA_SIGN_PERMIT)),
                    _hashStruct(PERMIT_TYPE, outerEncodeData)
                )
            ),
            appDomainSeparator,
            outerEncodeData,
            bytes(PERMIT_TYPE)
        );

        // Act
        bytes4 permitResult = _isValidSignature(
            instance,
            _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, permitEncodeData)),
            permitAsOuter
        );
        bytes4 outerResult = _isValidSignature(
            instance,
            _appHash(appDomainSeparator, _hashStruct(OUTER_TYPE, outerEncodeData)),
            outerAsPermit
        );

        // Assert
        assertEq(permitResult, INVALID_SIGNATURE, "Should reject a Permit under the Outer type");
        assertEq(outerResult, INVALID_SIGNATURE, "Should reject an Outer under the Permit type");
    }

    /*//////////////////////////////////////////////////////////////
                                  FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_NeverRevertsOnArbitrarySignature(
        bytes32 hash,
        bytes calldata body
    )
        public
    {
        // Arrange
        vm.assume(hash != ERC7739_DETECTION_HASH);
        _enableContentsAnySignature(appDomainSeparator, Solarray.strings(PERMIT_TYPE));

        // Act
        (bool reverted, bytes4 result) =
            _tryIsValidSignature(hash, abi.encodePacked(bytes1(0x01), body));

        // Assert
        assertFalse(reverted, "Should not revert");
        assertTrue(
            result == ERC1271_MAGIC_VALUE || result == INVALID_SIGNATURE,
            "Should return the magic value or INVALID_SIGNATURE"
        );
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_NeverRevertsOnArbitraryAppendedData(
        bytes32 hash,
        bool bindHash,
        bool honestTrailer,
        bytes32 domain,
        bytes calldata encodeData,
        bytes calldata description,
        uint16 wordCount,
        uint16 descriptionLength
    )
        public
    {
        // Arrange - the description is enabled, so a well-formed envelope reaches the session
        // validator
        PermissionId permissionId =
            _enableContentsAnySignature(domain, Solarray.strings(string(description)));
        if (honestTrailer) {
            wordCount = uint16(encodeData.length / 32);
            descriptionLength = uint16(description.length);
        }
        if (bindHash) hash = _appHash(domain, _hashStruct(string(description), encodeData));
        vm.assume(hash != ERC7739_DETECTION_HASH);
        bytes memory signature = abi.encodePacked(
            bytes1(0x01),
            permissionId,
            uint256(64),
            domain,
            encodeData,
            description,
            wordCount,
            descriptionLength
        );

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertTrue(
            result == ERC1271_MAGIC_VALUE || result == INVALID_SIGNATURE,
            "Should return the magic value or INVALID_SIGNATURE"
        );
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_CorrectEnvelope_ReturnsMagic(
        uint256 wordCount,
        bytes32[16] memory values,
        bool explicitMode
    )
        public
    {
        // Arrange
        wordCount = bound(wordCount, 1, 16);
        string memory contentsType = _fuzzType("Fuzz", "f", wordCount);
        bytes memory encodeData = _words(values, wordCount);
        bytes memory description =
            explicitMode ? abi.encodePacked(contentsType, "Fuzz") : bytes(contentsType);
        PermissionId permissionId =
            _enableContents(instance, appDomainSeparator, Solarray.strings(string(description)));
        bytes32 contents = _hashStruct(contentsType, encodeData);
        bytes32 digest = _typedDataSignDigest(
            instance.account,
            appDomainSeparator,
            _typedDataSignTypehash("Fuzz", contentsType),
            contents
        );
        bytes memory signature = _envelope(
            permissionId,
            _sign(sessionKey.privateKey, digest),
            appDomainSeparator,
            encodeData,
            description
        );

        // Act
        (bool reverted, bytes4 result) =
            _tryIsValidSignature(_appHash(appDomainSeparator, contents), signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept a correctly built envelope");
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_SingleByteFlip_ReturnsInvalid(
        uint256 wordCount,
        bytes32[16] memory values,
        bool explicitMode,
        uint256 region,
        uint256 position,
        uint8 mask
    )
        public
    {
        // Arrange - the session validator accepts any signature, so only the envelope rejects
        wordCount = bound(wordCount, 1, 16);
        region = bound(region, 0, 3);
        mask = uint8(bound(mask, 1, type(uint8).max));
        string memory contentsType = _fuzzType("Fuzz", "f", wordCount);
        bytes memory encodeData = _words(values, wordCount);
        bytes memory description =
            explicitMode ? abi.encodePacked(contentsType, "Fuzz") : bytes(contentsType);
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(string(description)));
        bytes32 hash = _appHash(appDomainSeparator, _hashStruct(contentsType, encodeData));
        bytes memory signature =
            _envelope(permissionId, "", appDomainSeparator, encodeData, description);
        (, bytes4 baseline) = _tryIsValidSignature(hash, signature);
        assertEq(baseline, ERC1271_MAGIC_VALUE, "Should accept the envelope before the flip");

        // The 65-byte header is followed by the app domain, encodeData, description and trailer
        uint256 start = 65;
        uint256 length = 32;
        if (region == 1) {
            start = 97;
            length = encodeData.length;
        } else if (region == 2) {
            start = 97 + encodeData.length;
            length = description.length;
        } else if (region == 3) {
            start = signature.length - 4;
            length = 4;
        }
        position = bound(position, start, start + length - 1);
        signature[position] ^= bytes1(mask);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a flipped byte");
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_TypeConfusion_NeverReturnsMagic(
        uint256 seedA,
        uint256 seedB,
        bool sameName,
        uint256 wordCount,
        bytes32[16] memory values,
        bool presentOtherWords,
        bytes32[16] memory otherValues
    )
        public
    {
        // Arrange - a struct hashed under typeB, presented under the enabled typeA, with a
        // session validator that accepts any signature
        if (!sameName) vm.assume(seedA != seedB);
        wordCount = bound(wordCount, 1, 16);
        string memory nameA = string.concat("T", LibString.toHexStringNoPrefix(seedA));
        string memory typeA = _fuzzType(nameA, "v", wordCount);
        string memory typeB = sameName
            ? _fuzzType(nameA, "w", wordCount)
            : _fuzzType(string.concat("T", LibString.toHexStringNoPrefix(seedB)), "v", wordCount);
        bytes memory encodeData = _words(values, wordCount);
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(typeA));
        bytes memory signature = _envelope(
            permissionId,
            "",
            appDomainSeparator,
            presentOtherWords ? _words(otherValues, wordCount) : encodeData,
            bytes(typeA)
        );

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            _appHash(appDomainSeparator, _hashStruct(typeB, encodeData)), signature
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, INVALID_SIGNATURE, "Should reject a struct of another type");
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_HeaderLength_MagicOnlyFromWellFormed64Bytes(
        uint256 headerLength,
        bool wellFormed,
        bytes32 randomWord,
        bytes32 otherRandomWord,
        bytes16 filler
    )
        public
    {
        // Arrange - a header of 0 to 80 bytes before a valid tail
        headerLength = bound(headerLength, 0, 80);
        PermissionId permissionId =
            _enableContentsAnySignature(appDomainSeparator, Solarray.strings(PERMIT_TYPE));
        vm.assume(randomWord != PermissionId.unwrap(permissionId));
        bytes memory source = wellFormed
            ? abi.encodePacked(permissionId, headerLength, filler)
            : abi.encodePacked(randomWord, otherRandomWord, filler);
        bytes memory encodeData = _permitEncodeData(1 ether);
        bytes memory signature = abi.encodePacked(
            bytes1(0x01),
            _prefix(source, headerLength),
            appDomainSeparator,
            encodeData,
            PERMIT_TYPE,
            uint16(encodeData.length / 32),
            uint16(bytes(PERMIT_TYPE).length)
        );

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(
            _appHash(appDomainSeparator, _hashStruct(PERMIT_TYPE, encodeData)), signature
        );

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(
            result,
            wellFormed && headerLength >= 64 ? ERC1271_MAGIC_VALUE : INVALID_SIGNATURE,
            "Should accept only a well-formed header of at least 64 bytes"
        );
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_NonProbeHash_NeverReturnsProbeValue(
        bytes32 hash,
        bytes calldata signature
    )
        public
    {
        // Arrange
        vm.assume(hash != ERC7739_DETECTION_HASH);

        // Act
        (, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertNotEq(result, ERC7739_SUPPORT_VALUE, "Should not return the ERC-7739 probe value");
    }

    function testFuzz_erc1271IsValidSignatureViaNestedEIP712_ProbeHash_ReturnsProbeValue(
        address sender,
        bytes calldata signature
    )
        public
        view
    {
        // Act
        bytes4 result = smartSessionEmissary.isValidSignatureWithSender(
            sender, ERC7739_DETECTION_HASH, signature
        );

        // Assert
        assertEq(result, ERC7739_SUPPORT_VALUE, "Should return the ERC-7739 probe value");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _permitEncodeData(uint256 amount) internal pure returns (bytes memory) {
        return abi.encode(address(0xBEEF), amount, uint256(0), uint256(1_700_000_000));
    }

    function _outerEncodeData() internal pure returns (bytes memory) {
        return abi.encode(_hashStruct(INNER_TYPE, abi.encode(uint256(7))), uint256(8));
    }

    function _hashPerson(string memory name, address wallet) internal pure returns (bytes32) {
        return _hashStruct(PERSON_TYPE, abi.encode(keccak256(bytes(name)), wallet));
    }

    /// @notice `name(uint256 <field>0,...,uint256 <field><wordCount - 1>)`
    function _fuzzType(
        string memory name,
        string memory field,
        uint256 wordCount
    )
        internal
        pure
        returns (string memory contentsType)
    {
        contentsType = string.concat(name, "(");
        for (uint256 i; i < wordCount; i++) {
            if (i != 0) contentsType = string.concat(contentsType, ",");
            contentsType = string.concat(contentsType, "uint256 ", field, LibString.toString(i));
        }
        contentsType = string.concat(contentsType, ")");
    }

    function _words(
        bytes32[16] memory values,
        uint256 wordCount
    )
        internal
        pure
        returns (bytes memory encodeData)
    {
        for (uint256 i; i < wordCount; i++) {
            encodeData = abi.encodePacked(encodeData, values[i]);
        }
    }

    function _prefix(bytes memory source, uint256 length) internal pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i; i < length; i++) {
            result[i] = source[i];
        }
        return result;
    }
}
