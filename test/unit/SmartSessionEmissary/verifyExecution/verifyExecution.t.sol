// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

// Types
import {
    Session,
    PolicyData,
    ActionData,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    PermissionId,
    SmartSessionMode
} from "@smartsessions/DataTypes.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT
} from "erc7579/lib/ModeLib.sol";

contract SmartSessionEmissary_verifyExecution_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes mockSignature;
    bytes mockExecData;
    bytes32 TEST_HASH;
    bytes4 mockTargetSelector;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Init variables
        mockSignature = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        TEST_HASH = keccak256("testHash");

        // Setup mock execution data for a single call
        mockTargetSelector = bytes4(keccak256("testFunction()"));
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        mockExecData = abi.encodeWithSelector(
            IERC7579Account.execute.selector,
            CALLTYPE_SINGLE,
            EXECTYPE_DEFAULT,
            target,
            value,
            callData
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    ///------------------------------///
    /// 1. UseMode                   ///
    ///------------------------------///

    function test_verifyExecution_UseMode_Success()
        public
        withWhitelistedThis
        withEnabledSudoSession
    {
        // Arrange
        bytes memory emissaryData =
            packEmissaryData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, emissaryData, mockExecData
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector"
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withWhitelistedThis() {
        // Prank to admin
        vm.prank(admin.addr);
        // Whitelist this contract
        smartSessionEmissary.setWhitelistedSource(address(this), true);
        // Continue with the test
        _;
    }

    modifier withEnabledSudoSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup Sudo Policy
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

        // Continue with the test
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function packEmissaryData(
        SmartSessionMode mode,
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(mode, permissionId, signature);
    }
}
