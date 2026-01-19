// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getSessionValidatorAndConfig_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getSessionValidatorAndConfig_ReturnsZero_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        (address validator, bytes memory config) =
            _lens().getSessionValidatorAndConfig(instance.account, fakePermissionId);

        // Assert
        assertEq(validator, address(0), "Validator should be zero address");
        assertEq(config.length, 0, "Config should be empty");
    }

    /*//////////////////////////////////////////////////////////////
                            WITH SESSION
    //////////////////////////////////////////////////////////////*/

    function test_getSessionValidatorAndConfig_ReturnsCorrectData_WhenSessionEnabled() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        (address validator, bytes memory config) =
            _lens().getSessionValidatorAndConfig(instance.account, permissionId);

        // Assert
        assertEq(validator, address(yesSessionValidator), "Should return correct validator");
        assertEq(config, bytes("mockInitData"), "Should return correct config");
    }

    function test_getSessionValidatorAndConfig_ReturnsDifferentValidators() public {
        // Arrange
        Session memory session1 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("salt1"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        Session memory session2 = _createActionSession(
            ISessionValidator(address(noSessionValidator)),
            keccak256("salt2"),
            target,
            bytes4(keccak256("approve()")),
            address(sudoPolicy)
        );

        PermissionId permissionId1 = _enableSession(session1, TEST_LOCK_TAG);
        PermissionId permissionId2 = _enableSession(session2, TEST_LOCK_TAG);

        // Act
        (address validator1,) =
            _lens().getSessionValidatorAndConfig(instance.account, permissionId1);
        (address validator2,) =
            _lens().getSessionValidatorAndConfig(instance.account, permissionId2);

        // Assert
        assertEq(validator1, address(yesSessionValidator), "Should return yes validator");
        assertEq(validator2, address(noSessionValidator), "Should return no validator");
    }

    /*//////////////////////////////////////////////////////////////
                               ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test session validator is isolated per permissionId
    function test_getSessionValidatorAndConfig_IsolatedPerPermissionId() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        (address validatorForOriginal,) =
            _lens().getSessionValidatorAndConfig(instance.account, permissionId);
        (address validatorForDifferent,) =
            _lens().getSessionValidatorAndConfig(instance.account, differentPermissionId);

        // Assert
        assertEq(validatorForOriginal, address(yesSessionValidator), "Should have validator");
        assertEq(
            validatorForDifferent,
            address(0),
            "Should NOT have validator for different permissionId"
        );
    }

    /// @notice Test session validator is isolated per account
    function test_getSessionValidatorAndConfig_IsolatedPerAccount() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        address differentAccount = makeAddr("differentAccount");

        // Act
        (address validatorForOriginal,) =
            _lens().getSessionValidatorAndConfig(instance.account, permissionId);
        (address validatorForDifferent,) =
            _lens().getSessionValidatorAndConfig(differentAccount, permissionId);

        // Assert
        assertEq(validatorForOriginal, address(yesSessionValidator), "Should have validator");
        assertEq(
            validatorForDifferent, address(0), "Should NOT have validator for different account"
        );
    }
}
