// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SignatureLib_Unit_Test } from "../SignatureLib.t.sol";

// Libraries
import { SignatureLib } from "@lib/SignatureLib.sol";

contract SignatureLib_recoverECDSA_Test is SignatureLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_recoverECDSA_Success_ValidSignature() public view {
        // Arrange
        bytes memory signature = createEOASignature(testHash, userPrivateKey);

        // Act
        address recovered = this.callRecoverECDSA(testHash, signature);

        // Assert
        assertEq(recovered, userEOA, "Should recover correct address");
    }

    function test_recoverECDSA_Success_DifferentSigners() public view {
        // Arrange
        bytes memory userSig = createEOASignature(testHash, userPrivateKey);
        bytes memory allocatorSig = createEOASignature(testHash, allocatorPrivateKey);
        bytes memory attackerSig = createEOASignature(testHash, attackerPrivateKey);

        // Act & Assert - Each signature recovers to correct address
        assertEq(this.callRecoverECDSA(testHash, userSig), userEOA);
        assertEq(this.callRecoverECDSA(testHash, allocatorSig), allocatorEOA);
        assertEq(this.callRecoverECDSA(testHash, attackerSig), attacker);
    }

    function test_recoverECDSA_Success_DifferentHashes() public view {
        // Arrange
        bytes32 hash1 = keccak256("message 1");
        bytes32 hash2 = keccak256("message 2");

        bytes memory sig1 = createEOASignature(hash1, userPrivateKey);
        bytes memory sig2 = createEOASignature(hash2, userPrivateKey);

        // Act
        address recovered1 = this.callRecoverECDSA(hash1, sig1);
        address recovered2 = this.callRecoverECDSA(hash2, sig2);

        // Assert - Same signer for both
        assertEq(recovered1, userEOA);
        assertEq(recovered2, userEOA);

        // Wrong hash with wrong signature should not recover to user
        address wrongRecovered = this.callRecoverECDSA(hash1, sig2);
        assertNotEq(wrongRecovered, userEOA);
    }

    function test_recoverECDSA_RevertsWhen_InvalidSignatureLength() public {
        // Arrange - Signature too short
        bytes memory shortSig = new bytes(64);

        // Act & Assert
        vm.expectRevert();
        this.callRecoverECDSA(testHash, shortSig);

        // Arrange - Signature too long
        bytes memory longSig = new bytes(66);

        // Act & Assert
        vm.expectRevert();
        this.callRecoverECDSA(testHash, longSig);
    }

    function test_recoverECDSA_RevertsWhen_InvalidValue() public {
        // Arrange - Create signature with invalid v value
        (, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, testHash);

        // Test various invalid v values
        uint8[4] memory invalidVValues = [uint8(0), uint8(1), uint8(26), uint8(29)];

        for (uint256 i = 0; i < invalidVValues.length; i++) {
            bytes memory invalidSig = abi.encodePacked(r, s, invalidVValues[i]);

            // Act & Assert
            vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("InvalidSignature()"))));
            this.callRecoverECDSA(testHash, invalidSig);
        }
    }

    function test_recoverECDSA_RevertsWhen_MalformedSignature() public {
        // Arrange - All zeros with valid v
        bytes memory zeroSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));

        // Act & Assert
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("InvalidSignature()"))));
        this.callRecoverECDSA(testHash, zeroSig);
    }

    function test_recoverECDSA_Differential_CompareWithEcrecover() public view {
        // Test that our implementation matches direct ecrecover
        bytes memory signature = createEOASignature(testHash, userPrivateKey);

        // Extract v, r, s
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // Compare with direct ecrecover
        address directRecover = ecrecover(testHash, v, r, s);
        address libRecover = this.callRecoverECDSA(testHash, signature);

        assertEq(libRecover, directRecover, "Should match ecrecover");
        assertEq(libRecover, userEOA, "Should be correct address");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function callRecoverECDSA(
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (address)
    {
        return SignatureLib.recoverECDSA(hash, signature);
    }
}
