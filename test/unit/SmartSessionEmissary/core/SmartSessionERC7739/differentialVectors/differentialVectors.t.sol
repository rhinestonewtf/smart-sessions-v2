// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { EIP712 } from "solady/utils/EIP712.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @notice Checks the emissary against ERC-7739 reference values computed with an independent
///         EIP-712 implementation: per struct the app hash, struct hash, `encodeData`, the
///         `TypedDataSign` digest for this suite's account, and a signature from a fixed key. The
///         Permit2 and Compact type strings hash to the compact-utils typehashes. Vectors that
///         sign the standard sorted `TypedDataSign` for a type whose dependency sorts first are
///         expected to be rejected. Regenerate them if the suite's account or its `eip712Domain`
///         changes.
contract SmartSessionERC7739_differentialVectors_Test is SmartSessionERC7739_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant VECTOR_COUNT = 21;

    /// @notice The address of the key that signed the vectors
    address constant SIGNER = 0x9C43C09A98f7D067755CCB15Bd8452322BFf08ea;

    /// @notice The account domain the vectors were signed for
    string constant ACCOUNT_NAME = "uMSA advanced/withHook";
    string constant ACCOUNT_VERSION = "v0.1";
    uint256 constant ACCOUNT_CHAIN_ID = 31_337;
    address constant ACCOUNT_VERIFYING_CONTRACT = 0x0d1586c4ea176d9dadB2ca48D025dC4A14291794;
    bytes32 constant ACCOUNT_SALT = bytes32(0);

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct Vector {
        string label;
        string primaryType;
        string contentsType;
        bytes description;
        bytes32 appDomainSeparator;
        bytes encodeData;
        bytes32 contents;
        bytes32 appHash;
        bytes32 typedDataSignTypehash;
        bytes32 digest;
        bytes signature;
        bool expectValid;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_differentialVectors_AccountDomainMatchesVectors() public view {
        // Act
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = EIP712(instance.account).eip712Domain();

        // Assert
        assertEq(name, ACCOUNT_NAME, "Account domain name");
        assertEq(version, ACCOUNT_VERSION, "Account domain version");
        assertEq(chainId, ACCOUNT_CHAIN_ID, "Account chainId");
        assertEq(verifyingContract, ACCOUNT_VERIFYING_CONTRACT, "Account verifyingContract");
        assertEq(salt, ACCOUNT_SALT, "Account domain salt");
    }

    function test_differentialVectors_HelpersAgreeWithReferenceValues() public view {
        // Arrange
        uint256 count = _count();
        assertGt(count, 0, "Should load vectors");

        for (uint256 i; i < count; i++) {
            Vector memory vector = _vector(i);

            // Act
            bytes32 contents = _hashStruct(vector.contentsType, vector.encodeData);
            bytes32 typehash = _typedDataSignTypehash(vector.primaryType, vector.contentsType);

            // Assert
            assertEq(contents, vector.contents, string.concat(vector.label, ": contents"));
            assertEq(
                _appHash(vector.appDomainSeparator, contents),
                vector.appHash,
                string.concat(vector.label, ": app hash")
            );
            assertEq(
                typehash,
                vector.typedDataSignTypehash,
                string.concat(vector.label, ": TypedDataSign typehash")
            );
            if (vector.expectValid) {
                assertEq(
                    _typedDataSignDigest(
                        instance.account, vector.appDomainSeparator, typehash, contents
                    ),
                    vector.digest,
                    string.concat(vector.label, ": digest")
                );
            }
        }
    }

    function test_differentialVectors_ReferenceSignedEnvelope_ReturnsExpected() public {
        // Arrange
        uint256 count = _count();
        uint256 valid;

        for (uint256 i; i < count; i++) {
            Vector memory vector = _vector(i);
            uint256 snapshot = vm.snapshotState();
            PermissionId permissionId = _enableVector(vector);
            bytes memory signature = _envelope(
                permissionId,
                vector.signature,
                vector.appDomainSeparator,
                vector.encodeData,
                vector.description
            );

            // Act
            (bool reverted, bytes4 result) = _tryIsValidSignature(vector.appHash, signature);

            // Assert
            assertFalse(reverted, string.concat(vector.label, ": should not revert"));
            assertEq(
                result,
                vector.expectValid ? ERC1271_MAGIC_VALUE : INVALID_SIGNATURE,
                string.concat(vector.label, ": result")
            );
            if (vector.expectValid) valid++;
            vm.revertToState(snapshot);
        }
        assertGt(valid, 0, "Should accept at least one vector");
        assertLt(valid, count, "Should reject the sorted TypedDataSign vectors");
    }

    function test_differentialVectors_ThroughAccount_ReturnsExpected() public {
        // Arrange
        uint256 count = _count();

        for (uint256 i; i < count; i++) {
            Vector memory vector = _vector(i);
            uint256 snapshot = vm.snapshotState();
            PermissionId permissionId = _enableVector(vector);
            bytes memory signature = _envelope(
                permissionId,
                vector.signature,
                vector.appDomainSeparator,
                vector.encodeData,
                vector.description
            );

            // Act
            bytes4 result = _isValidSignature(instance, vector.appHash, signature);

            // Assert
            assertEq(
                result,
                vector.expectValid ? ERC1271_MAGIC_VALUE : INVALID_SIGNATURE,
                string.concat(vector.label, ": result through the account")
            );
            vm.revertToState(snapshot);
        }
    }

    function test_differentialVectors_revertsWhen_EncodeDataMutated() public {
        // Arrange
        uint256 count = _count();

        for (uint256 i; i < count; i++) {
            Vector memory vector = _vector(i);
            uint256 snapshot = vm.snapshotState();
            PermissionId permissionId = _enableVector(vector);
            bytes memory encodeData = bytes.concat(vector.encodeData);
            encodeData[(i * 7) % encodeData.length] ^= 0x01;
            bytes memory signature = _envelope(
                permissionId,
                vector.signature,
                vector.appDomainSeparator,
                encodeData,
                vector.description
            );

            // Act
            (bool reverted, bytes4 result) = _tryIsValidSignature(vector.appHash, signature);

            // Assert
            assertFalse(reverted, string.concat(vector.label, ": should not revert"));
            assertEq(result, INVALID_SIGNATURE, string.concat(vector.label, ": mutated encodeData"));
            vm.revertToState(snapshot);
        }
    }

    function test_differentialVectors_revertsWhen_SignatureMutated() public {
        // Arrange - one bit of `s` flipped
        uint256 count = _count();

        for (uint256 i; i < count; i++) {
            Vector memory vector = _vector(i);
            uint256 snapshot = vm.snapshotState();
            PermissionId permissionId = _enableVector(vector);
            bytes memory validatorSignature = bytes.concat(vector.signature);
            validatorSignature[63] ^= 0x01;
            bytes memory signature = _envelope(
                permissionId,
                validatorSignature,
                vector.appDomainSeparator,
                vector.encodeData,
                vector.description
            );

            // Act
            (bool reverted, bytes4 result) = _tryIsValidSignature(vector.appHash, signature);

            // Assert
            assertFalse(reverted, string.concat(vector.label, ": should not revert"));
            assertEq(result, INVALID_SIGNATURE, string.concat(vector.label, ": mutated signature"));
            vm.revertToState(snapshot);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _count() internal pure returns (uint256) {
        return VECTOR_COUNT;
    }

    function _vector(uint256 i) internal pure returns (Vector memory vector) {
        if (i == 0) {
            vector.label = "Permit, implicit";
            vector.primaryType = "Permit";
            vector.contentsType =
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
            vector.description = bytes(
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
            );
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006553f100";
            vector.contents = 0xb6e8729388f92e5a2dd473f22675488afb04d14a0ff0fd5d7869a43fed70eb8a;
            vector.appHash = 0x4d58c7544b3aa856f51cb534bef9f228788da8a468b391138d76f541438967f2;
            vector.typedDataSignTypehash =
            0x4f1c3ab2cf2c3e0522801e514ad6298def2a626ea5c98dec07d36b617c911dea;
            vector.digest = 0x80085a137e8e8ff96c886184a6047ed74ed7484c468e5ec8cb4f47fc43a7304b;
            vector.signature =
                hex"a9d44965fb4119069e8b82e41c019d407f2e0a200a972cebbcd4b9e81b183b7b4570dec041c2df30c330c55f1d2e47fc56716e666014f4575c8b3198f2ea4cf81b";
            vector.expectValid = true;
        } else if (i == 1) {
            vector.label = "Permit, explicit";
            vector.primaryType = "Permit";
            vector.contentsType =
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
            vector.description = bytes(
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)Permit"
            );
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006553f100";
            vector.contents = 0xb6e8729388f92e5a2dd473f22675488afb04d14a0ff0fd5d7869a43fed70eb8a;
            vector.appHash = 0x4d58c7544b3aa856f51cb534bef9f228788da8a468b391138d76f541438967f2;
            vector.typedDataSignTypehash =
            0x4f1c3ab2cf2c3e0522801e514ad6298def2a626ea5c98dec07d36b617c911dea;
            vector.digest = 0x80085a137e8e8ff96c886184a6047ed74ed7484c468e5ec8cb4f47fc43a7304b;
            vector.signature =
                hex"a9d44965fb4119069e8b82e41c019d407f2e0a200a972cebbcd4b9e81b183b7b4570dec041c2df30c330c55f1d2e47fc56716e666014f4575c8b3198f2ea4cf81b";
            vector.expectValid = true;
        } else if (i == 2) {
            vector.label = "Permit, app domain with salt";
            vector.primaryType = "Permit";
            vector.contentsType =
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
            vector.description = bytes(
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
            );
            vector.appDomainSeparator =
            0x7179d33391b9db3ddc949bbf1e57edc458b70d1a73db8a5e15622659bb4acc60;
            vector.encodeData =
                hex"0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000beef80000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006553f100";
            vector.contents = 0xecb10836c8d549647026f35bdf84133715da59e954b39d82ebd46eb560d1cc12;
            vector.appHash = 0xf629e61dfd40d7a6b29d27bd087631ccb2e9158907183f66c3b9b0b88bba4110;
            vector.typedDataSignTypehash =
            0x4f1c3ab2cf2c3e0522801e514ad6298def2a626ea5c98dec07d36b617c911dea;
            vector.digest = 0x27da59dcc9634cbeec21a1e19ab8fb22deac050a7bfd6e51a480fa2b4470d015;
            vector.signature =
                hex"e11cb173d357f6b75687f740da02c9a1bc83e2e596b6e3e6486154edee843ceb3e870b3bf2392ec15a4c77374eec5f45db5eb4280dfb213a0c2dd3477a0a5ad61c";
            vector.expectValid = true;
        } else if (i == 3) {
            vector.label = "Permit, app domain with only chainId and verifyingContract";
            vector.primaryType = "Permit";
            vector.contentsType =
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
            vector.description = bytes(
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
            );
            vector.appDomainSeparator =
            0xe33aecfec3b714a68a52217dde2fe5eb67c8d1446e80b1d9a314cc4d0b482a27;
            vector.encodeData =
                hex"0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006553f100";
            vector.contents = 0x69d88a712b4f56605bc9bebccf6155242628088ef361a0d00b2d0960572e4e2b;
            vector.appHash = 0x87bc57b839b81ac49a62d5d6f14f66616adef2b26c87aa32300f8676baec26e5;
            vector.typedDataSignTypehash =
            0x4f1c3ab2cf2c3e0522801e514ad6298def2a626ea5c98dec07d36b617c911dea;
            vector.digest = 0xf7bd89f8a3d709361dcdab4039f569878fad6413ec9fd3db9e5e955613446808;
            vector.signature =
                hex"a9101fc15396c69d0b1bb852e4a6f25164f0f1906db1fc4ecee242af77e15e634e63e71b63a33aa393d4e3bcb6c9918a8f7ffa18208ae6bf78e9b7a6a9452cc81c";
            vector.expectValid = true;
        } else if (i == 4) {
            vector.label = "Atomic types: bool, int256, bytes4, uint8, int8, bytes32";
            vector.primaryType = "Flags";
            vector.contentsType =
            "Flags(bool on,int256 delta,bytes4 selector,uint8 small,int8 negative,bytes32 tag)";
            vector.description = bytes(
                "Flags(bool on,int256 delta,bytes4 selector,uint8 small,int8 negative,bytes32 tag)"
            );
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"0000000000000000000000000000000000000000000000000000000000000001fffffffffffffffffffffffffffffffffffffff360d3632fb98b1215c0000000a9059cbb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8097721080eade4b057eae589a1435045aca04c882598f794915100d4634a2c909";
            vector.contents = 0x27298063382a5476a8d3fb98792ec1d2818bdea72be75c427d65fb5c0be84aa7;
            vector.appHash = 0x452161e0fdefbb518c0a3d574f1a21f4b57dbf65deb73a45694703ccc3eb88e5;
            vector.typedDataSignTypehash =
            0x4fde978b1c51a45924f0db21b14d716a4465152af348d033ba6def6fd68cca95;
            vector.digest = 0x96632d7c211a32dc60452c5fa914dd591c6d62361841c1834076c716ec9832f8;
            vector.signature =
                hex"097ac91f8dc2891e143850f8e64939dfea2d74d06afd7f006677757a39033a366ea280589599dcf83a8f1b6f04f99f7073bf48de14cace1ec2d72da9d1bc42441c";
            vector.expectValid = true;
        } else if (i == 5) {
            vector.label = "string and bytes fields";
            vector.primaryType = "Message";
            vector.contentsType = "Message(string text,bytes payload,bytes32 id)";
            vector.description = bytes("Message(string text,bytes payload,bytes32 id)");
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8d4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1a709fd3aa96d9faf770e44a5aef2f4808a6fe3a5ddf546568f36ad3a3873f31d";
            vector.contents = 0xc08409a84a5270cc12fd0aa090a0f27438a38ad9e26c53a9d7b0bf4a8a48a6c1;
            vector.appHash = 0x91eea190d3b505985421032fa0a6e0ffadab761c8f348370e2a31cb6e95ca4c8;
            vector.typedDataSignTypehash =
            0x2d61a82714b30640ce5efc47f31288d3d8f122ddaf36ec327c75387fea37f98b;
            vector.digest = 0x14f20c17e415559439226b5f1294041362d2be7647b43c167105c51185be231b;
            vector.signature =
                hex"2f15f6aec5c35fea79e80eea40553b804f1eb3b425b5610d983bf7c84922d605369fa3f087a714803ac2ae2705703676e425fc03343eae43878679cd62d0fcaf1b";
            vector.expectValid = true;
        } else if (i == 6) {
            vector.label = "unicode string and 100-byte bytes";
            vector.primaryType = "Message";
            vector.contentsType = "Message(string text,bytes payload,bytes32 id)";
            vector.description = bytes("Message(string text,bytes payload,bytes32 id)Message");
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"d8ac1cc718ea27353f8319a8b1ddec9c38076e1bf8c2e0761360d1e0709e54d9816afb32e7661842252bc955167ea1e36fde4ac8cfe932978b9dcdb04aee8ca40000000000000000000000000000000000000000000000000000000000000000";
            vector.contents = 0x6d7faa1861b11560f6526fd48e7aa2a3b8ca10cf15e08fba811654f0c26ed57e;
            vector.appHash = 0x35464169048fdb5e358dddd26c372a50a1c1d6bfaada0a23b98ac75e91a40227;
            vector.typedDataSignTypehash =
            0x2d61a82714b30640ce5efc47f31288d3d8f122ddaf36ec327c75387fea37f98b;
            vector.digest = 0xc2409b0890f2e9dbe3e3e5ed81f0ecf9cab7bfc36513175c5650bf81d1576d6a;
            vector.signature =
                hex"e18ac34117a7b0ec308bf374ed6a0fef3008f40d80d8e5a2b60a5fb71f3cc2cf4cb146826a5e1ec702d6408fe855910aa9a1cf859db162bec73e0f6eb5c18dc31c";
            vector.expectValid = true;
        } else if (i == 7) {
            vector.label = "empty string and empty bytes";
            vector.primaryType = "Message";
            vector.contentsType = "Message(string text,bytes payload,bytes32 id)";
            vector.description = bytes("Message(string text,bytes payload,bytes32 id)");
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            vector.contents = 0x6e4d23120aad8729e9e655344bc40ee2e92baa7453b0419f29475103ac21fc72;
            vector.appHash = 0x32b7179f01524855b883b0b2b8ba50f355b9992075289dc24710002f5833ef1e;
            vector.typedDataSignTypehash =
            0x2d61a82714b30640ce5efc47f31288d3d8f122ddaf36ec327c75387fea37f98b;
            vector.digest = 0x0dfb41fe8fd343cab7ab3261264f0a85c461621cb2b415b37f398713bff346a1;
            vector.signature =
                hex"53acdf3c5989e51c38412568eb229a184c386f15adc88aeb43c3d6cb3a70dc9e28994279626f4042cc91e1da0d6f04c8387cf3526b2a891a02705fbdc01019fd1c";
            vector.expectValid = true;
        } else if (i == 8) {
            vector.label = "atomic, string and fixed-size arrays";
            vector.primaryType = "Batch";
            vector.contentsType =
            "Batch(uint256[] amounts,address[] recipients,string[] memos,uint256[3] grid)";
            vector.description = bytes(
                "Batch(uint256[] amounts,address[] recipients,string[] memos,uint256[3] grid)"
            );
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"6e0c627900b24bd432fe7b1f713f1b0744091a646a9fe4a65a18dfed21f2949c463f844151f18ccee377b57a06172686855bea0a1cac14ccb9b8858a4322c6b76ce2bcd7d6891602e85533ea74ee7294709d441fa062cb7abff0ad638d83269be412f2638c2b1d81853e7a87a9168480e4d2dff55e31289127d1f9ceb5f69a14";
            vector.contents = 0xbf517b8cde853dc6b7fdcf3ebb8d3d98f0687e3b29a227c39c7cedf43a5bc0c9;
            vector.appHash = 0x6cb11ce5ffc1e999da25d2cf6613e9f0959e7945abeba2159ea56498ca4b9346;
            vector.typedDataSignTypehash =
            0x57450ee5470d1d5eb893e0d687a9625fb896f59a95dabedc4c6503ab494c5ff1;
            vector.digest = 0x44dace265c17f097be7160267ed5dd1f8cd8aa1cfa5ece01e29d22d54493b110;
            vector.signature =
                hex"d8f50133c85f7528d2f067723f0e0891bff212e0e39485ebe6d634755e9a9f91368e0ca7677e5820d44cb260e9b6c199aef4778af0cf0dd6bc32f1cff268aa471c";
            vector.expectValid = true;
        } else if (i == 9) {
            vector.label = "empty arrays";
            vector.primaryType = "Batch";
            vector.contentsType =
            "Batch(uint256[] amounts,address[] recipients,string[] memos,uint256[3] grid)";
            vector.description = bytes(
                "Batch(uint256[] amounts,address[] recipients,string[] memos,uint256[3] grid)Batch"
            );
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47046700b4d40ac5c35af2c22dda2787a91eb567b06c924a8fb8ae9a05b20c08c21";
            vector.contents = 0xf7db356de892c3c44b2a31e67ca5fe5798801f08a66bdee76f6ddb16afaec7d9;
            vector.appHash = 0x2509655a3eb7757d91246eab4e80df0f12cf2e0fd4a9ce53695e469122de9679;
            vector.typedDataSignTypehash =
            0x57450ee5470d1d5eb893e0d687a9625fb896f59a95dabedc4c6503ab494c5ff1;
            vector.digest = 0xe766daaaaf5391074df02af267a1a080059b28aa23ec9bf6cb3fa09b54a51dfd;
            vector.signature =
                hex"d60c0427691958abb05228d6cc3915761665485f7895803d691f8c009b298f0277f42b1494000e0d2211931243dee1940e886a817f299939655d44823ddb32101b";
            vector.expectValid = true;
        } else if (i == 10) {
            vector.label = "EIP-712 Mail example";
            vector.primaryType = "Mail";
            vector.contentsType =
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
            vector.description = bytes(
                "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
            );
            vector.appDomainSeparator =
            0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f;
            vector.encodeData =
                hex"fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8";
            vector.contents = 0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e;
            vector.appHash = 0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2;
            vector.typedDataSignTypehash =
            0x9647875519c02faf032f868cc0bd84287ea4ef1377642a59e3e684975e11a6d9;
            vector.digest = 0x67a3bf6409c995a6976aace2c7e240059b4ca8cd1931cc1d3f6b7e1c5885fec8;
            vector.signature =
                hex"6c3a0fa4c6e58f9653d04a953799fb4f47b4117a728fe3c7798ab402b5b8e1fa1cacc3e3ae9f3db8a035db3de13b8f9932fc5861734b4405e6207443795159a91b";
            vector.expectValid = true;
        } else if (i == 11) {
            vector.label = "EIP-712 Mail example, explicit";
            vector.primaryType = "Mail";
            vector.contentsType =
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
            vector.description = bytes(
                "Mail(Person from,Person to,string contents)Person(string name,address wallet)Mail"
            );
            vector.appDomainSeparator =
            0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f;
            vector.encodeData =
                hex"fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8";
            vector.contents = 0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e;
            vector.appHash = 0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2;
            vector.typedDataSignTypehash =
            0x9647875519c02faf032f868cc0bd84287ea4ef1377642a59e3e684975e11a6d9;
            vector.digest = 0x67a3bf6409c995a6976aace2c7e240059b4ca8cd1931cc1d3f6b7e1c5885fec8;
            vector.signature =
                hex"6c3a0fa4c6e58f9653d04a953799fb4f47b4117a728fe3c7798ab402b5b8e1fa1cacc3e3ae9f3db8a035db3de13b8f9932fc5861734b4405e6207443795159a91b";
            vector.expectValid = true;
        } else if (i == 12) {
            vector.label = "array of structs, three types";
            vector.primaryType = "Basket";
            vector.contentsType =
                "Basket(Item[] items,address owner,Meta meta)Item(address token,uint256 amount,bytes32[] tags)Meta(string note,bytes blob)";
            vector.description = bytes(
                "Basket(Item[] items,address owner,Meta meta)Item(address token,uint256 amount,bytes32[] tags)Meta(string note,bytes blob)"
            );
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"e776392db46b4c19b58700e844cdf9fdc9413a8052d18b4b207ac017408f4df4000000000000000000000000666666666666666666666666666666666666666617ce4bc2161bd40f6ac9f037e13a99e1a3a71462f6f8bb8f41e9f6966650d1d4";
            vector.contents = 0xc7c1a11b1a4b8970764e7a168759ee5b5d269ad7e9387fb8426b656f1cf036ac;
            vector.appHash = 0x2f4e728ae457fd75b28bd2888a6e116c391aad5c2e0bfeb1a4879897398cccfc;
            vector.typedDataSignTypehash =
            0xb234e788304ebe45a601c0a48095b24f43c3fd6f97b6e7242b1958a773c66a49;
            vector.digest = 0x99f2e37cba574408cd0dd2fa34ea3442dd1e22e649f98a143cb1b18099a3af8e;
            vector.signature =
                hex"4452d16d84f7709654fc0cb4c1480c1d3839a43d30ebfcfdf693306a2372bdce6297ca9d1a8f7006e362626cd69e61d4549060a5f8efd3143d6e177fccc13d761c";
            vector.expectValid = true;
        } else if (i == 13) {
            vector.label = "three levels deep";
            vector.primaryType = "A";
            vector.contentsType = "A(B b,uint256 x)B(C[] c,string s)C(bytes data,bool flag)";
            vector.description = bytes("A(B b,uint256 x)B(C[] c,string s)C(bytes data,bool flag)");
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"15771dd0bf720d5db58d5ca6a4abdaa2e4d318c89bff7bc3840d2d5fe190a7bf000000000000000000000000000000000000000000000000000000000000002a";
            vector.contents = 0xea47fb8b69637c51d6d6b997b8b8e3574133de7664f349472e0ee214d8fc8009;
            vector.appHash = 0x7fbfba8ee49ce560e9b5767aba774d604462309ee87abdf15024f3f586a4735f;
            vector.typedDataSignTypehash =
            0x286805628eb4c20d5dceee01cbb6e04673aa193f53d8113e13ef108ee1892d2c;
            vector.digest = 0xe93eb5f71e1d6532812b4289861fdae1981a2389939c031720721ac2e92416a5;
            vector.signature =
                hex"f42e48cacadec2ed50ae1f33d018ec9bcd67bafe955d738e5de9349104cfd2777372374e02343f8027c064ec11cd1b4d04a65d268126c31b5481348b598c739b1c";
            vector.expectValid = true;
        } else if (i == 14) {
            vector.label = "Outer, primary first";
            vector.primaryType = "Outer";
            vector.contentsType = "Outer(Inner a,uint256 b)Inner(uint256 x)";
            vector.description = bytes("Outer(Inner a,uint256 b)Inner(uint256 x)");
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"af668b07c12c4eb02580e485d71cfefde1b918335e0119302fa9954587833a890000000000000000000000000000000000000000000000000000000000000008";
            vector.contents = 0xd43d63dd0ea50f79ebdeaed22f74e564176b7459e4aa33b944d6cc0044f934aa;
            vector.appHash = 0x0700e6b640a1faa16ab0f11dd74946f7eef08955cbf291fa80f42c798d67cc74;
            vector.typedDataSignTypehash =
            0xdc9737ca0cf655a14bc5eefc1275b72da44717e795aa61ab2925922c31f59d61;
            vector.digest = 0xaa63b52d57a5c18db38f77a3e1c632334e6f4abbb04bd11c5e0d36788e7673c4;
            vector.signature =
                hex"44e4ffeca80379bd9fd7ce20e84f15a04926149fe75db7578f3a85fd1a6d9d560c0e8bf7889ca9ad27d5342a402ac97f035a6f9263a355ed95bf04164cd2dd7b1b";
            vector.expectValid = true;
        } else if (i == 15) {
            vector.label = "Outer, sorted TypedDataSign";
            vector.primaryType = "Outer";
            vector.contentsType = "Outer(Inner a,uint256 b)Inner(uint256 x)";
            vector.description = bytes("Outer(Inner a,uint256 b)Inner(uint256 x)");
            vector.appDomainSeparator =
            0x6ddb2898e09e3252b28b0e2e8f4b48e5261939ccf2aa726b07e792aa98fda44b;
            vector.encodeData =
                hex"af668b07c12c4eb02580e485d71cfefde1b918335e0119302fa9954587833a890000000000000000000000000000000000000000000000000000000000000008";
            vector.contents = 0xd43d63dd0ea50f79ebdeaed22f74e564176b7459e4aa33b944d6cc0044f934aa;
            vector.appHash = 0x0700e6b640a1faa16ab0f11dd74946f7eef08955cbf291fa80f42c798d67cc74;
            vector.typedDataSignTypehash =
            0xdc9737ca0cf655a14bc5eefc1275b72da44717e795aa61ab2925922c31f59d61;
            vector.digest = 0x036b807fe5ec392615a672a1395ad69da92cf06f1c42b86295c4bde8c62f1132;
            vector.signature =
                hex"b93e083f8d4a87c6b31b32d907382926db6d8821277381e83b7d4377ba469f36475ab1219963641ac558d6e51c305245077d5c6273786c7f04ea2c658d4680251b";
            vector.expectValid = false;
        } else if (i == 16) {
            vector.label = "Permit2 batch witness with Mandate, primary first";
            vector.primaryType = "PermitBatchWitnessTransferFrom";
            vector.contentsType =
                "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mandate mandate)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)TokenPermissions(address token,uint256 amount)";
            vector.description = bytes(
                "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mandate mandate)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)TokenPermissions(address token,uint256 amount)"
            );
            vector.appDomainSeparator =
            0x866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28;
            vector.encodeData =
                hex"d982bd20b8c0a934821c20a97f51904b664af3e0ee0f42d3d4ccc6804eac3a9700000000000000000000000099999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000006553ff10faa5bfcf72d593e6f5ad408cef4dc18644d7c865b13567eb0cbcb47e16f54f6d";
            vector.contents = 0x6265e8239688b8b6626203ff124997195d8c2c8a599608496bebb69be9ad0a43;
            vector.appHash = 0x44e960657aaa06a244acd16f92dd1cfdd03e34c9122a68d34ba30f4b35ca3d0d;
            vector.typedDataSignTypehash =
            0x873a294910cbac0265027c00eb6c96f589c09dc4162e34bc810600b6b9d19e52;
            vector.digest = 0xcf55f7645c2c4aa477e1f31ebd64504c13472c9773254e0c8b0d25195a5357e8;
            vector.signature =
                hex"f64f8a3522d5c9c0004427ecbc194196a9acef1e4410dac0bb6ef985f949df6830bec86f55d3fce0c40ffe06a27bdb821bb2da8de202aaa5d5bd325a9214926e1c";
            vector.expectValid = true;
        } else if (i == 17) {
            vector.label = "Permit2 batch witness with Mandate, primary first, explicit";
            vector.primaryType = "PermitBatchWitnessTransferFrom";
            vector.contentsType =
                "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mandate mandate)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)TokenPermissions(address token,uint256 amount)";
            vector.description = bytes(
                "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mandate mandate)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)TokenPermissions(address token,uint256 amount)PermitBatchWitnessTransferFrom"
            );
            vector.appDomainSeparator =
            0x866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28;
            vector.encodeData =
                hex"d982bd20b8c0a934821c20a97f51904b664af3e0ee0f42d3d4ccc6804eac3a9700000000000000000000000099999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000006553ff10faa5bfcf72d593e6f5ad408cef4dc18644d7c865b13567eb0cbcb47e16f54f6d";
            vector.contents = 0x6265e8239688b8b6626203ff124997195d8c2c8a599608496bebb69be9ad0a43;
            vector.appHash = 0x44e960657aaa06a244acd16f92dd1cfdd03e34c9122a68d34ba30f4b35ca3d0d;
            vector.typedDataSignTypehash =
            0x873a294910cbac0265027c00eb6c96f589c09dc4162e34bc810600b6b9d19e52;
            vector.digest = 0xcf55f7645c2c4aa477e1f31ebd64504c13472c9773254e0c8b0d25195a5357e8;
            vector.signature =
                hex"f64f8a3522d5c9c0004427ecbc194196a9acef1e4410dac0bb6ef985f949df6830bec86f55d3fce0c40ffe06a27bdb821bb2da8de202aaa5d5bd325a9214926e1c";
            vector.expectValid = true;
        } else if (i == 18) {
            vector.label = "Permit2 batch witness with Mandate, sorted TypedDataSign";
            vector.primaryType = "PermitBatchWitnessTransferFrom";
            vector.contentsType =
                "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mandate mandate)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)TokenPermissions(address token,uint256 amount)";
            vector.description = bytes(
                "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mandate mandate)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)TokenPermissions(address token,uint256 amount)"
            );
            vector.appDomainSeparator =
            0x866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28;
            vector.encodeData =
                hex"d982bd20b8c0a934821c20a97f51904b664af3e0ee0f42d3d4ccc6804eac3a9700000000000000000000000099999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000006553ff10faa5bfcf72d593e6f5ad408cef4dc18644d7c865b13567eb0cbcb47e16f54f6d";
            vector.contents = 0x6265e8239688b8b6626203ff124997195d8c2c8a599608496bebb69be9ad0a43;
            vector.appHash = 0x44e960657aaa06a244acd16f92dd1cfdd03e34c9122a68d34ba30f4b35ca3d0d;
            vector.typedDataSignTypehash =
            0x873a294910cbac0265027c00eb6c96f589c09dc4162e34bc810600b6b9d19e52;
            vector.digest = 0xb3d20c0396cbff0d02449b53cfed39d52a58b783d7ce1327647d13c359d3d868;
            vector.signature =
                hex"d62ebac7b88b9266c2a4affca085c7b5f589e6c1bcab2a41baf9775701a2b5551e3a54299c0acddae1b69fc6dd145e85515b5b8066f1c3f5365f09c7048d50ca1b";
            vector.expectValid = false;
        } else if (i == 19) {
            vector.label = "Compact MultichainCompact, primary first";
            vector.primaryType = "MultichainCompact";
            vector.contentsType =
                "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)";
            vector.description = bytes(
                "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)"
            );
            vector.appDomainSeparator =
            0x4ac11bdf0eb5972bae47825af851d20c342d88f466669ec58827be03650df019;
            vector.encodeData =
                hex"0000000000000000000000000d1586c4ea176d9dadb2ca48d025dc4a142917940000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000006553ff106de629a5408b2409a6993336553f44f72002ba7925aa5bf0a421403580e33cbb";
            vector.contents = 0x20e0486c9107dbbe80c74127b895b71b6f69e2f992c1274c8ee20691f678ea8f;
            vector.appHash = 0x8a04878e294bc034af4953bdb4f8434ad5264f41283314ca6837a285453aa4f1;
            vector.typedDataSignTypehash =
            0x10e1c45eba165145144b9cee5746cb26882592f077d678fe969cc487b947eeab;
            vector.digest = 0x7fe2a24fcc30c1f598cf825887e87e25331b0f5972fb1845b3b3f363a949f09f;
            vector.signature =
                hex"c154af37a8928ee68316959a4c2db7c1e7e1fda3f5ece75de8ca5912c9e2e71934478e2cb2ba592004031ff1ff0be86bad1509f508119abe22c4f2ae6f657faf1b";
            vector.expectValid = true;
        } else if (i == 20) {
            vector.label = "Compact MultichainCompact, sorted TypedDataSign";
            vector.primaryType = "MultichainCompact";
            vector.contentsType =
                "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)";
            vector.description = bytes(
                "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,uint128 minGas,Op originOps,Op destOps,bytes32 q)Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)"
            );
            vector.appDomainSeparator =
            0x4ac11bdf0eb5972bae47825af851d20c342d88f466669ec58827be03650df019;
            vector.encodeData =
                hex"0000000000000000000000000d1586c4ea176d9dadb2ca48d025dc4a142917940000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000006553ff106de629a5408b2409a6993336553f44f72002ba7925aa5bf0a421403580e33cbb";
            vector.contents = 0x20e0486c9107dbbe80c74127b895b71b6f69e2f992c1274c8ee20691f678ea8f;
            vector.appHash = 0x8a04878e294bc034af4953bdb4f8434ad5264f41283314ca6837a285453aa4f1;
            vector.typedDataSignTypehash =
            0x10e1c45eba165145144b9cee5746cb26882592f077d678fe969cc487b947eeab;
            vector.digest = 0xbbae9ac740400935b907e5e8060239892bf8e76dcc7dfc50e54a0567b6678fc7;
            vector.signature =
                hex"9ab24c2b8d04ac66a1c19fa1b364cd66d71925b59f5fd739887e8507298a093e00bd93b0aa173481d6fbe7b7553dcc9f56363d772be632c00144cf825436651e1c";
            vector.expectValid = false;
        } else {
            revert("no such vector");
        }
    }

    /// @notice Enables the vector's description under its app domain, for the vectors' signer
    function _enableVector(Vector memory vector) internal returns (PermissionId) {
        address[] memory owners = new address[](1);
        owners[0] = SIGNER;
        string[] memory descriptions = new string[](1);
        descriptions[0] = string(vector.description);
        return _enableContents({
            account: instance,
            validator: ISessionValidator(address(ownableValidator)),
            validatorInitData: abi.encode(uint256(1), owners),
            domain: vector.appDomainSeparator,
            descriptions: descriptions
        });
    }
}
