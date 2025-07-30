// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SignatureLib_Unit_Test } from "../SignatureLib.t.sol";

// Libraries
import { SignatureLib } from "@lib/SignatureLib.sol";

contract SignatureLib_verifySignatures_Test is SignatureLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifySignatures_Success_InitMode_BothEOA() public {
        // Arrange
        bytes memory allocatorSig = ""; // Not checked in init mode
        bytes memory userSig = createEOASignature(testHash, userPrivateKey);

        // Act - msg.sender is neither allocator nor user
        vm.prank(address(this));

        // Assert - Should not revert in init mode with both EOA
        this.callVerifySignatures(
            testHash,
            allocatorEOA,
            userEOA,
            allocatorSig,
            userSig,
            true // isInit - allocator sig not checked
        );
    }

    function test_verifySignatures_Success_InitMode_UserWallet() public {
        // Arrange
        bytes memory allocatorSig = ""; // Not checked in init mode
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act - msg.sender is neither allocator nor user
        vm.prank(address(this));

        // Assert - Should not revert in init mode with user as smart account
        this.callVerifySignatures(
            testHash,
            allocatorEOA, // Can be EOA since not checked in init
            userWallet, // Must be smart account since msg.sender != user
            allocatorSig,
            userSig,
            true // isInit
        );
    }

    function test_verifySignatures_RevertsWhen_MsgSenderIsUser_AllocatorEOA() public {
        // Arrange
        bytes memory allocatorSig = createEOASignature(testHash, allocatorPrivateKey);
        bytes memory userSig = createEOASignature(testHash, userPrivateKey);

        // Act - msg.sender is the user (user signature not checked)
        vm.prank(userEOA);

        // Assert - Should revert since allocator is EOA
        vm.expectRevert();
        this.callVerifySignatures(
            testHash,
            allocatorEOA,
            userEOA,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_Success_MsgSenderIsUser_AllocatorWallet() public {
        // Arrange
        bytes memory allocatorSig = createSmartAccountSignature(testHash, allocatorPrivateKey);
        bytes memory userSig = createEOASignature(testHash, userPrivateKey);

        // Act - msg.sender is the user (user signature not checked)
        vm.prank(userEOA);

        // Assert - Should not revert
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userEOA,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_Success_BothWallets() public {
        // Arrange - Both are smart accounts
        bytes memory allocatorSig = createSmartAccountSignature(testHash, allocatorPrivateKey);
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act
        vm.prank(address(this));

        // Assert - Should not revert
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userWallet,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_MixedEOAAndWallet() public {
        // Arrange - Allocator is EOA, User is wallet
        bytes memory allocatorSig = createEOASignature(testHash, allocatorPrivateKey);
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act
        vm.prank(address(this));

        // Assert - Should not revert because allocator is EOA
        vm.expectRevert();
        this.callVerifySignatures(
            testHash,
            allocatorEOA,
            userWallet,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_InvalidAllocatorSignature_EOA() public {
        // Arrange
        bytes memory invalidAllocatorSig = createEOASignature(testHash, attackerPrivateKey);
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert();
        this.callVerifySignatures(
            testHash,
            allocatorEOA,
            userWallet,
            invalidAllocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_InvalidAllocatorSignature_Wallet() public {
        // Arrange
        bytes memory invalidAllocatorSig = createSmartAccountSignature(testHash, attackerPrivateKey);
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert();
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userWallet,
            invalidAllocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_InvalidUserSignature_Wallet() public {
        // Arrange
        bytes memory allocatorSig = createSmartAccountSignature(testHash, allocatorPrivateKey);
        bytes memory invalidUserSig = createEOASignature(testHash, attackerPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidUserSignature.selector);
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userWallet,
            allocatorSig,
            invalidUserSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_WrongHashForAllocator() public {
        // Arrange - Sign different hash
        bytes memory allocatorSig = createSmartAccountSignature(invalidHash, allocatorPrivateKey);
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidAllocatorSignature.selector);
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userWallet,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_WrongHashForUser() public {
        // Arrange - Sign different hash
        bytes memory allocatorSig = createSmartAccountSignature(testHash, allocatorPrivateKey);
        bytes memory userSig = createSmartAccountSignature(invalidHash, userPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidUserSignature.selector);
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userWallet,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_MalformedAllocatorSignature() public {
        // Arrange
        bytes memory malformedSig = createMalformedSignature();
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidAllocatorSignature.selector);
        this.callVerifySignatures(
            testHash,
            allocatorEOA,
            userWallet,
            malformedSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_RevertsWhen_WalletReturnsInvalid() public {
        // Arrange - Deploy wallet that returns invalid
        address failingWallet = deployFailingWallet();

        bytes memory allocatorSig = createSmartAccountSignature(testHash, allocatorPrivateKey);
        bytes memory userSig = createEOASignature(testHash, userPrivateKey);

        // Act & Assert
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidUserSignature.selector);
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            failingWallet,
            allocatorSig,
            userSig,
            false // not init
        );
    }

    function test_verifySignatures_EmptySignatures() public {
        // Arrange
        bytes memory emptySig = "";

        // Act & Assert - Empty signatures should fail
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidUserSignature.selector);
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userWallet,
            emptySig,
            emptySig,
            false // not init
        );
    }

    function test_verifySignatures_ZeroAllocatorAddress() public {
        // Arrange
        bytes memory sig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act & Assert - Zero allocator address
        vm.prank(address(this));
        vm.expectRevert(SignatureLib.InvalidAllocatorSignature.selector);
        this.callVerifySignatures(
            testHash,
            address(0),
            userWallet,
            sig,
            sig,
            false // not init
        );
    }

    function test_verifySignatures_InitModeSkipsAllocatorCheck() public {
        // Arrange - Invalid allocator signature but valid user signature
        bytes memory invalidAllocatorSig = createEOASignature(testHash, attackerPrivateKey);
        bytes memory userSig = createSmartAccountSignature(testHash, userPrivateKey);

        // Act
        vm.prank(address(this));

        // Assert - Should not revert because isInit=true skips allocator check
        this.callVerifySignatures(
            testHash,
            allocatorEOA,
            userWallet,
            invalidAllocatorSig,
            userSig,
            true // isInit
        );
    }

    function test_verifySignatures_MsgSenderIsUserSkipsUserCheck() public {
        // Arrange - Invalid user signature but msg.sender is user
        bytes memory allocatorSig = createSmartAccountSignature(testHash, allocatorPrivateKey);
        bytes memory invalidUserSig = createEOASignature(testHash, attackerPrivateKey);

        // Act
        vm.prank(userEOA);

        // Assert - Should not revert because msg.sender == user
        this.callVerifySignatures(
            testHash,
            allocatorWallet,
            userEOA,
            allocatorSig,
            invalidUserSig,
            false // not init
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function callVerifySignatures(
        bytes32 hash,
        address allocator,
        address user,
        bytes calldata allocatorSignature,
        bytes calldata userSignature,
        bool isInit
    )
        external
        view
    {
        SignatureLib.verifySignatures(
            hash, allocator, user, allocatorSignature, userSignature, isInit
        );
    }
}
