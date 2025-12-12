// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isInitialized_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isInitialized_ReturnsFalse_WhenNoSessions() public view {
        // Act
        bool isInit = _lens().isInitialized(instance.account);

        // Assert
        assertFalse(isInit, "Should return false when no sessions");
    }

    function test_isInitialized_ReturnsFalse_ForDifferentAccount() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        _enableSession(session, TEST_LOCK_TAG);

        address differentAccount = makeAddr("differentAccount");

        // Act
        bool isInit = _lens().isInitialized(differentAccount);

        // Assert
        assertFalse(isInit, "Should return false for different account");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isInitialized_ReturnsTrue_WhenSessionEnabled() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        _enableSession(session, TEST_LOCK_TAG);

        // Act
        bool isInit = _lens().isInitialized(instance.account);

        // Assert
        assertTrue(isInit, "Should return true when session enabled");
    }

    function test_isInitialized_ReturnsTrue_WhenMultipleSessionsEnabled() public {
        // Arrange
        Session memory session1 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("salt1"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        Session memory session2 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("salt2"),
            target,
            bytes4(keccak256("approve()")),
            address(sudoPolicy)
        );

        _enableSession(session1, TEST_LOCK_TAG);
        _enableSession(session2, TEST_LOCK_TAG);

        // Act
        bool isInit = _lens().isInitialized(instance.account);

        // Assert
        assertTrue(isInit, "Should return true with multiple sessions");
    }
}

