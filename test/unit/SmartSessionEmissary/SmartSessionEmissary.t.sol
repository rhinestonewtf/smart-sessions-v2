// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";
import { Solarray } from "solarray/Solarray.sol";

// Contracts
import { SmartSessionEmissaryMock } from "@test/mock/SmartSessionEmissaryMock.sol";
import { AddressBook } from "@mocks/MockAddressBook.sol";

// Interfaces
import { ISmartSessionLens } from "@interfaces/ISmartSessionLens.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { IntegrationEncodeLib } from "@smartsessions-test/utils/lib/IntegrationEncodeLib.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";

// Types
import {
    PermissionId,
    ActionId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context,
    ChainDigest
} from "@smartsessions/DataTypes.sol";
import { Session, EnableSession } from "@types/DataTypes.sol";

contract SmartSessionEmissary_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using HashLibV2 for ChainDigest[];

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant INVALID_SIGNATURE = 0xffffffff;
    bytes12 constant NO_LOCK_TAG = bytes12(0);

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionEmissary contract instance.
    SmartSessionEmissaryMock internal smartSessionEmissary;

    /// @notice Mock intent executor address.
    address internal MOCK_INTENT_EXECUTOR;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Define the mock intent executor address.
        MOCK_INTENT_EXECUTOR = makeAddr("MockIntentExecutor");
        // Deploy the SmartSessionEmissary contract.
        smartSessionEmissary =
            new SmartSessionEmissaryMock(address(new AddressBook(MOCK_INTENT_EXECUTOR)));
        // Label the contract for better readability in traces.
        vm.label(address(smartSessionEmissary), "SmartSessionEmissary");
    }

    /*//////////////////////////////////////////////////////////////
                            SESSION HELPERS
    //////////////////////////////////////////////////////////////*/

    function makeMultiChainEnableData(
        Session memory session,
        address, /*validator*/
        bytes12 lockTag,
        uint256 expires,
        address,
        address /*allocator*/
    )
        internal
        view
        returns (EnableSession memory enableData)
    {
        bytes32 sessionDigest = _lens()
            .getSessionDigest({
                lockTag: lockTag, account: instance.account, data: session, expires: expires
            });

        ChainDigest[] memory chainDigests = IntegrationEncodeLib.encodeHashesAndChainIds(
            Solarray.uint64s(181_818, uint64(block.chainid), 777),
            Solarray.bytes32s(sessionDigest, sessionDigest, sessionDigest)
        );

        enableData = EnableSession({
            chainDigestIndex: 1, hashesAndChainIds: chainDigests, sessionToEnable: session
        });
    }

    /// @notice Creates a basic session with action policies
    function _createActionSession(
        ISessionValidator validator,
        bytes32 salt,
        address actionTarget,
        bytes4 actionSelector,
        address policy
    )
        internal
        pure
        returns (Session memory)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: policy, initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: actionTarget,
            actionTargetSelector: actionSelector,
            actionPolicies: policyDatas
        });

        ERC7739Data memory erc7739Data;

        return Session({
            sessionValidator: validator,
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: new PolicyData[](0)
        });
    }

    /// @notice Creates a session with multiple actions
    function _createMultiActionSession(
        ISessionValidator validator,
        bytes32 salt,
        ActionData[] memory actions
    )
        internal
        pure
        returns (Session memory)
    {
        ERC7739Data memory erc7739Data;

        return Session({
            sessionValidator: validator,
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: new PolicyData[](0)
        });
    }

    /// @notice Creates a basic session with claim policies
    function _createClaimSession(
        ISessionValidator validator,
        bytes32 salt,
        address policy
    )
        internal
        pure
        returns (Session memory)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: policy, initData: "" });

        ERC7739Data memory erc7739Data;

        return Session({
            sessionValidator: validator,
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
        });
    }

    /// @notice Creates a session with ERC7739 policies
    function _createERC7739Session(
        ISessionValidator validator,
        bytes32 salt,
        address policy,
        bytes32 appDomainSeparator,
        string memory contentName
    )
        internal
        pure
        returns (Session memory)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: policy, initData: "" });

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = contentName;
        allowedContent[0].appDomainSeparator = appDomainSeparator;

        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: allowedContent, erc1271Policies: policyDatas });

        return Session({
            sessionValidator: validator,
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });
    }

    /// @notice Creates a full session with all policy types
    function _createFullSession(
        ISessionValidator validator,
        bytes32 salt,
        address actionTarget,
        bytes4 actionSelector,
        address actionPolicy,
        address claimPolicy,
        address erc7739Policy,
        bytes32 appDomainSeparator,
        string memory contentName
    )
        internal
        pure
        returns (Session memory)
    {
        // Action policies
        PolicyData[] memory actionPolicies = new PolicyData[](1);
        actionPolicies[0] = PolicyData({ policy: actionPolicy, initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: actionTarget,
            actionTargetSelector: actionSelector,
            actionPolicies: actionPolicies
        });

        // Claim policies
        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: claimPolicy, initData: "" });

        // ERC7739 policies
        PolicyData[] memory erc1271Policies = new PolicyData[](1);
        erc1271Policies[0] = PolicyData({ policy: erc7739Policy, initData: "" });

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = contentName;
        allowedContent[0].appDomainSeparator = appDomainSeparator;

        ERC7739Data memory erc7739Data = ERC7739Data({
            allowedERC7739Content: allowedContent, erc1271Policies: erc1271Policies
        });

        return Session({
            sessionValidator: validator,
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: claimPolicies
        });
    }

    /*//////////////////////////////////////////////////////////////
                            ENABLE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session and returns the permissionId
    function _enableSession(
        Session memory session,
        bytes12 lockTag
    )
        internal
        returns (PermissionId)
    {
        vm.prank(instance.account);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds = smartSessionEmissary.enableSessions(sessions, lockTag);
        return permissionIds[0];
    }

    /// @notice external wrapper for multichainDigest that can be called in tests
    function multichainDigest(ChainDigest[] calldata chainDigests) external pure returns (bytes32) {
        return chainDigests.multichainDigest();
    }

    /*//////////////////////////////////////////////////////////////
                                  LENS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets the lens interface
    function _lens() internal view returns (ISmartSessionLens) {
        return ISmartSessionLens(address(smartSessionEmissary));
    }

    /*//////////////////////////////////////////////////////////////
                           ACTION ID HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates an ActionId from target and selector
    function _toActionId(address actionTarget, bytes4 selector) internal pure returns (ActionId) {
        return ActionId.wrap(keccak256(abi.encodePacked(actionTarget, selector)));
    }

    /*//////////////////////////////////////////////////////////////
                          ACTION DATA HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a single ActionData
    function _createActionData(
        address actionTarget,
        bytes4 actionSelector,
        address policy
    )
        internal
        pure
        returns (ActionData memory)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: policy, initData: "" });

        return ActionData({
            actionTarget: actionTarget,
            actionTargetSelector: actionSelector,
            actionPolicies: policyDatas
        });
    }
}
