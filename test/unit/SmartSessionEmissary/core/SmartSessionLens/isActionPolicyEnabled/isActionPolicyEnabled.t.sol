// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId, ActionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isActionPolicyEnabled_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    bytes4 testSelector;
    ActionId testActionId;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        testSelector = bytes4(keccak256("transfer()"));
        testActionId = _toActionId(target, testSelector);
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isActionPolicyEnabled_ReturnsFalse_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isEnabled = _lens()
            .isActionPolicyEnabled(
                instance.account, fakePermissionId, testActionId, address(sudoPolicy)
            );

        // Assert
        assertFalse(isEnabled, "Should return false for non-existent session");
    }

    function test_isActionPolicyEnabled_ReturnsFalse_ForDifferentPolicy() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            testSelector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        address differentPolicy = makeAddr("differentPolicy");

        // Act
        bool isEnabled = _lens()
            .isActionPolicyEnabled(instance.account, permissionId, testActionId, differentPolicy);

        // Assert
        assertFalse(isEnabled, "Should return false for different policy");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isActionPolicyEnabled_ReturnsTrue_WhenEnabled() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            testSelector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bool isEnabled = _lens()
            .isActionPolicyEnabled(
                instance.account, permissionId, testActionId, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabled, "Should return true for enabled policy");
    }

    /*//////////////////////////////////////////////////////////////
                               ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test action policies are isolated per permissionId
    function test_isActionPolicyEnabled_IsolatedPerPermissionId() public {
        // Arrange
        bytes4 selector = bytes4(keccak256("transfer()"));
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            selector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);
        ActionId actionId = _toActionId(target, selector);

        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        bool isEnabledForOriginal = _lens()
            .isActionPolicyEnabled(instance.account, permissionId, actionId, address(sudoPolicy));
        bool isEnabledForDifferent = _lens()
            .isActionPolicyEnabled(
                instance.account, differentPermissionId, actionId, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original permissionId");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different permissionId");
    }

    /// @notice Test action policies are isolated per actionId
    function test_isActionPolicyEnabled_IsolatedPerActionId() public {
        // Arrange
        bytes4 selector = bytes4(keccak256("transfer()"));
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            selector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        ActionId enabledActionId = _toActionId(target, selector);
        ActionId differentActionId = _toActionId(target, bytes4(keccak256("approve()")));

        // Act
        bool isEnabledForOriginal = _lens()
            .isActionPolicyEnabled(
                instance.account, permissionId, enabledActionId, address(sudoPolicy)
            );
        bool isEnabledForDifferent = _lens()
            .isActionPolicyEnabled(
                instance.account, permissionId, differentActionId, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original actionId");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different actionId");
    }

    /// @notice Test action policies are isolated per policy address
    function test_isActionPolicyEnabled_IsolatedPerPolicy() public {
        // Arrange
        bytes4 selector = bytes4(keccak256("transfer()"));
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            selector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);
        ActionId actionId = _toActionId(target, selector);

        address differentPolicy = makeAddr("differentPolicy");

        // Act
        bool isEnabledForOriginal = _lens()
            .isActionPolicyEnabled(instance.account, permissionId, actionId, address(sudoPolicy));
        bool isEnabledForDifferent = _lens()
            .isActionPolicyEnabled(instance.account, permissionId, actionId, differentPolicy);

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original policy");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different policy");
    }

    /// @notice Test action policies are isolated per account
    function test_isActionPolicyEnabled_IsolatedPerAccount() public {
        // Arrange
        bytes4 selector = bytes4(keccak256("transfer()"));
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            selector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);
        ActionId actionId = _toActionId(target, selector);

        address differentAccount = makeAddr("differentAccount");

        // Act
        bool isEnabledForOriginal = _lens()
            .isActionPolicyEnabled(instance.account, permissionId, actionId, address(sudoPolicy));
        bool isEnabledForDifferent = _lens()
            .isActionPolicyEnabled(differentAccount, permissionId, actionId, address(sudoPolicy));

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original account");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different account");
    }
}

